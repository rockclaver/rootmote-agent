package redact

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Placeholders swaps hostnames and public IP addresses for stable labels
// (host-N, ip-N) before text leaves the server. One instance is meant to
// cover one request so the same value always maps to the same label.
type Placeholders struct {
	mu     sync.Mutex
	hostRE *regexp.Regexp    // nil when there are no hostnames
	labels map[string]string // lower-case hostname or short form -> host-N
	short  map[string]bool   // keys of labels that are short forms
	ips    map[netip.Addr]string
}

// NewPlaceholders builds Placeholders for the given hostnames. Distinct
// hostnames (case-insensitive) are numbered host-1, host-2, ... in order.
// The short form before the first dot is also replaced when it is at least
// four characters long.
func NewPlaceholders(hostnames ...string) *Placeholders {
	p := &Placeholders{
		labels: map[string]string{},
		short:  map[string]bool{},
		ips:    map[netip.Addr]string{},
	}
	n := 0
	for _, h := range hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if _, ok := p.labels[h]; ok && !p.short[h] {
			continue
		}
		n++
		label := fmt.Sprintf("host-%d", n)
		p.labels[h] = label
		delete(p.short, h)
		if i := strings.IndexByte(h, '.'); i >= 4 {
			// Remember the label for the short form unless a full
			// hostname already claimed that key.
			if _, taken := p.labels[h[:i]]; !taken {
				p.labels[h[:i]] = label
				p.short[h[:i]] = true
			}
		}
	}
	if len(p.labels) == 0 {
		return p
	}
	names := make([]string, 0, len(p.labels))
	for k := range p.labels {
		names = append(names, regexp.QuoteMeta(k))
	}
	// Longest first so a full hostname wins over its own short form.
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) > len(names[j])
		}
		return names[i] < names[j]
	})
	p.hostRE = regexp.MustCompile(`(?i)` + strings.Join(names, "|"))
	return p
}

var (
	reIPv4Lit  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6Cand = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*|\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// Apply replaces known hostnames and public IP literals in s.
func (p *Placeholders) Apply(s string) string {
	if p == nil {
		return s
	}
	s = p.replaceHosts(s)
	return p.replaceIPs(s)
}

func isHostChar(b byte) bool {
	return b == '-' || b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func (p *Placeholders) replaceHosts(s string) string {
	if p.hostRE == nil {
		return s
	}
	locs := p.hostRE.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if start > 0 {
			prev := s[start-1]
			if isHostChar(prev) || prev == '.' && p.short[strings.ToLower(s[start:end])] {
				continue
			}
		}
		if end < len(s) && isHostChar(s[end]) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(p.labels[strings.ToLower(s[start:end])])
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// replaceIPs handles IPv6 and IPv4 literals in one left-to-right pass so
// numbering follows order of appearance.
func (p *Placeholders) replaceIPs(s string) string {
	return reIPv6Cand.ReplaceAllStringFunc(s, func(tok string) string {
		if strings.Count(tok, ":") < 2 {
			// Not IPv6; may still hold an IPv4 literal (e.g. "8.8.8.8:80").
			return p.replaceIPv4(tok)
		}
		// Trim trailing sentence punctuation until the token parses.
		for end := len(tok); end > 0; end-- {
			if addr, err := netip.ParseAddr(tok[:end]); err == nil {
				if !isPublic(addr) {
					return tok
				}
				return p.ipLabel(addr) + tok[end:]
			}
			if c := tok[end-1]; c != '.' && c != ':' {
				break
			}
		}
		return tok
	})
}

func (p *Placeholders) replaceIPv4(s string) string {
	return reIPv4Lit.ReplaceAllStringFunc(s, func(tok string) string {
		addr, err := netip.ParseAddr(tok)
		if err != nil || !isPublic(addr) {
			return tok
		}
		return p.ipLabel(addr)
	})
}

func (p *Placeholders) ipLabel(addr netip.Addr) string {
	addr = addr.Unmap()
	p.mu.Lock()
	defer p.mu.Unlock()
	if l, ok := p.ips[addr]; ok {
		return l
	}
	l := fmt.Sprintf("ip-%d", len(p.ips)+1)
	p.ips[addr] = l
	return l
}

var nonPublicPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this" network
		"100.64.0.0/10",   // CGNAT
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved + broadcast
		"2001:db8::/32",   // documentation
		"64:ff9b::/96",    // NAT64 well-known prefix
		"100::/64",        // discard-only
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// isPublic reports whether addr is a globally routable unicast address.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() {
		return false
	}
	for _, pre := range nonPublicPrefixes {
		if pre.Contains(addr) {
			return false
		}
	}
	return true
}
