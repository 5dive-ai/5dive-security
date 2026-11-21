// Package scope loads the control plane's scope.json and enforces it on every
// network connection the scanner makes.
//
// The scope is the authorization. Targets are IP literals of the sealed clone; the
// host names are the owner's real domains, which in public DNS point at the LIVE
// box. So a host name is only ever sent as an HTTP Host header or a TLS SNI value
// and is never resolved: the Guard refuses any address that is not an in-scope IP
// literal, before the connection reaches a dialer or a resolver.
package scope

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scope is the control plane's scope.json.
type Scope struct {
	RunID     string   `json:"run_id"`
	Owner     Owner    `json:"owner"`
	Targets   []Target `json:"targets"`
	HostNames []string `json:"host_names"`
	Depth     string   `json:"depth"`
	// OwnerNote is the owner's optional hint for the planner (DIVE-8984): what to
	// look at first. It is data for the planner, never an authorization: it adds no
	// target, tool or permission, and the scope lock and the gate stay as they are.
	OwnerNote string `json:"owner_note,omitempty"`
}

// MaxOwnerNote is the longest owner note, in characters.
const MaxOwnerNote = 500

// Depths. Deep is the owner's opt-in deeper sweep (DIVE-8925): every TCP port
// instead of the common ones. Same tools, same gate, same scope: deeper, not wider.
const (
	Shallow = "shallow"
	Deep    = "deep"
)

// Owner names the server the clone was made from.
type Owner struct {
	ServerID int64  `json:"server_id"`
	Domain   string `json:"domain"`
}

// Target is one scan target. Only kind "ip" exists.
type Target struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ErrRefused marks every scope refusal.
var ErrRefused = errors.New("scope refused")

var hostNameRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Load reads and validates a scope file.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrRefused, path, err)
	}
	var s Scope
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%w: parse %s: %v", ErrRefused, path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.HostNames == nil {
		s.HostNames = []string{}
	}
	if s.Depth == "" {
		s.Depth = Shallow
	}
	s.OwnerNote = strings.TrimSpace(s.OwnerNote)
	return &s, nil
}

// Validate refuses a scope that is empty, names a non-IP target, or asks for a
// depth the engine does not have.
func (s *Scope) Validate() error {
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
	}
	if strings.TrimSpace(s.RunID) == "" {
		return refuse("run_id is empty")
	}
	if len(s.Targets) == 0 {
		return refuse("no targets")
	}
	for i, t := range s.Targets {
		if t.Kind != "ip" {
			return refuse("target %d: kind %q is not allowed (only \"ip\")", i, t.Kind)
		}
		ip, err := netip.ParseAddr(t.Value)
		if err != nil || ip.Zone() != "" {
			return refuse("target %d: %q is not an IP literal", i, t.Value)
		}
		if ip.IsUnspecified() || ip.IsMulticast() {
			return refuse("target %d: %q is not a host address", i, t.Value)
		}
	}
	for i, h := range s.HostNames {
		if !hostNameRE.MatchString(h) || len(h) > 253 {
			return refuse("host_names[%d]: %q is not a host name", i, h)
		}
	}
	switch s.Depth {
	case "", Shallow, Deep:
	default:
		return refuse("depth %q is not available (only \"shallow\" or \"deep\")", s.Depth)
	}
	if n := utf8.RuneCountInString(s.OwnerNote); n > MaxOwnerNote {
		return refuse("owner_note is %d characters (at most %d)", n, MaxOwnerNote)
	}
	if !utf8.ValidString(s.OwnerNote) || strings.IndexFunc(s.OwnerNote, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
		return refuse("owner_note holds control characters")
	}
	return nil
}

// IPs returns the target addresses.
func (s *Scope) IPs() []netip.Addr {
	out := make([]netip.Addr, 0, len(s.Targets))
	for _, t := range s.Targets {
		out = append(out, netip.MustParseAddr(t.Value).Unmap())
	}
	return out
}

// AllowsIP reports whether ip is one of the targets.
func (s *Scope) AllowsIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, t := range s.IPs() {
		if t == ip {
			return true
		}
	}
	return false
}

// AllowsHostName reports whether name is one of the owner's host names.
func (s *Scope) AllowsHostName(name string) bool {
	for _, h := range s.HostNames {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	return false
}

// CheckAddress accepts "ip" or "ip:port" when ip is an in-scope literal. Any
// name is refused without being looked up.
func (s *Scope) CheckAddress(address string) (netip.Addr, error) {
	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q is not an IP literal; names are never resolved", ErrRefused, host)
	}
	if !s.AllowsIP(ip) {
		return netip.Addr{}, fmt.Errorf("%w: %s is not a target of this run", ErrRefused, ip)
	}
	return ip.Unmap(), nil
}

// DialFunc is the shape of net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Guard is the only way the scanner opens a connection.
type Guard struct {
	Scope *Scope
	next  DialFunc
}

// NewGuard wraps next (nil = a plain net.Dialer that has no working resolver).
func NewGuard(s *Scope, next DialFunc) *Guard {
	if next == nil {
		d := &net.Dialer{Resolver: noResolver}
		next = d.DialContext
	}
	return &Guard{Scope: s, next: next}
}

// noResolver fails every lookup, so even a bug that slipped a name past the Guard
// could not reach DNS through the default dialer.
var noResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, fmt.Errorf("%w: DNS lookups are disabled", ErrRefused)
	},
}

// DialContext refuses anything but an in-scope IP literal with a port.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("%w: network %q is not allowed", ErrRefused, network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: bad address %q", ErrRefused, address)
	}
	ip, err := g.Scope.CheckAddress(host)
	if err != nil {
		return nil, err
	}
	return g.next(ctx, network, net.JoinHostPort(ip.String(), port))
}
