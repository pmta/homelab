package ip

import (
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

var (
	// RFC7239 Forwarded: for= token may be quoted. Capture token after for=
	forwardedForRe = regexp.MustCompile(`for=(?:"?)([^\s;,\"]+)(?:"?)`)
	trustedNetsMu  sync.RWMutex
	trustedNets    []*net.IPNet
	whitelistNetsMu sync.RWMutex
	whitelistNets   []*net.IPNet
	verbose        bool
)

// SetTrustedCIDRs parses CIDR strings and sets the trusted proxy networks used
// when deriving client IPs. Call once at startup.
func SetTrustedCIDRs(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// allow bare IPs too
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
				continue
			}
		}
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return err
		}
		nets = append(nets, network)
	}
	trustedNetsMu.Lock()
	trustedNets = nets
	trustedNetsMu.Unlock()
	return nil
}

// SetVerbose enables or disables verbose logging inside the ip package.
func SetVerbose(v bool) {
	verbose = v
}

func isTrustedIP(ip net.IP) bool {
	trustedNetsMu.RLock()
	defer trustedNetsMu.RUnlock()
	if ip == nil { return false }
	for _, n := range trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SetWhitelistCIDRs sets CIDRs that will be treated as whitelisted for rate-limiting
// and other bypass checks. Call once at startup.
func SetWhitelistCIDRs(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				var mask net.IPMask
				if ip.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
				continue
			}
		}
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return err
		}
		nets = append(nets, network)
	}
	whitelistNetsMu.Lock()
	whitelistNets = nets
	whitelistNetsMu.Unlock()
	return nil
}

// IsWhitelisted reports whether the provided IP string (IPv4 or IPv6) is in the whitelist.
func IsWhitelisted(ipStr string) bool {
	ip := net.ParseIP(strings.Trim(ipStr, "[]"))
	if ip == nil { return false }
	whitelistNetsMu.RLock()
	defer whitelistNetsMu.RUnlock()
	for _, n := range whitelistNets {
		if n.Contains(ip) { return true }
	}
	return false
}

// DeriveClientIP returns the best-effort public client IP for the request.
// When trusted proxy CIDRs are configured via SetTrustedCIDRs, forwarding
// headers are only considered if the immediate peer (RemoteAddr) is trusted.
// Precedence: Forwarded (RFC7239) -> X-Forwarded-For (after trimming trusted proxies) -> X-Real-IP -> CF-Connecting-IP -> RemoteAddr
func DeriveClientIP(r *http.Request) string {
	// determine remote peer IP
	remote := r.RemoteAddr
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	remote = strings.Trim(remote, "[]")
	remoteIP := net.ParseIP(remote)

	// if remote peer is not trusted, ignore forwarding headers
	if remoteIP == nil || !isTrustedIP(remoteIP) {
		if remoteIP != nil {
			if verbose { log.Printf("remote %s not trusted; ignoring forwarding headers", remoteIP.String()) }
			return remoteIP.String()
		}
		if verbose { log.Printf("remote address unparsable: %q", r.RemoteAddr) }
		return ""
	}

	// helper to parse and validate an IP string
	parseIPStr := func(s string) net.IP {
		s = stripPort(strings.TrimSpace(s))
		s = strings.Trim(s, "[]")
		return net.ParseIP(s)
	}

	// 1. Forwarded header (may contain multiple for= entries)
	if f := r.Header.Get("Forwarded"); f != "" {
		matches := forwardedForRe.FindAllStringSubmatch(f, -1)
		if len(matches) > 0 {
			vals := make([]string, 0, len(matches))
			for _, m := range matches {
				if len(m) >= 2 {
					tok := strings.Trim(m[1], `"`)
					tok = stripPort(tok)
					if tok == "" || strings.EqualFold(tok, "unknown") { continue }
					vals = append(vals, tok)
				}
			}
			if ip := pickFromChain(vals); ip != nil {
				return ip.String()
			}
		}
	}

	// 2. X-Forwarded-For
	// 2. X-Forwarded-For and common alternatives
	xffHeaders := []string{"X-Forwarded-For", "X-Client-IP", "X-Cluster-Client-Ip"}
	for _, h := range xffHeaders {
		if xff := r.Header.Get(h); xff != "" {
			parts := strings.Split(xff, ",")
			vals := make([]string, 0, len(parts))
			for _, p := range parts {
				tok := strings.TrimSpace(p)
				tok = strings.Trim(tok, `"`)
				if tok == "" || strings.EqualFold(tok, "unknown") { continue }
				vals = append(vals, tok)
			}
			if ip := pickFromChain(vals); ip != nil {
				return ip.String()
			}
		}
	}

	// 3. X-Real-IP
	// 3. X-Real-IP (common)
	if xr := r.Header.Get("X-Real-Ip"); xr != "" {
		xr = strings.Trim(xr, `"`)
		if ip := parseIPStr(xr); ip != nil { return ip.String() }
	}

	// also consider some other single-value headers
	if xc := r.Header.Get("X-Client-IP"); xc != "" {
		xc = strings.Trim(xc, `"`)
		if ip := parseIPStr(xc); ip != nil { return ip.String() }
	}

	// 4. Cloudflare header
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		cf = strings.Trim(cf, `"`)
		if ip := parseIPStr(cf); ip != nil { return ip.String() }
	}

	// fallback to remote
	if remoteIP != nil { return remoteIP.String() }
	return ""
}

// pickFromChain applies trusted-proxies trimming: remove trailing entries that are trusted,
// then return the rightmost remaining entry as the client IP. Returns nil if none valid.
func pickFromChain(vals []string) net.IP {
	ips := make([]net.IP, 0, len(vals))
	for _, v := range vals {
		if v == "" || strings.EqualFold(v, "unknown") { continue }
		tok := stripPort(strings.TrimSpace(v))
		tok = strings.Trim(tok, `"`)
		ip := net.ParseIP(tok)
		if ip == nil {
			if verbose { log.Printf("ignoring malformed IP token: %q", v) }
		}
		ips = append(ips, ip)
	}
	// trim trailing trusted
	i := len(ips) - 1
	for i >= 0 {
		if ips[i] == nil { i--; continue }
		if isTrustedIP(ips[i]) { i--; continue }
		break
	}
	if i >= 0 && ips[i] != nil {
		return ips[i]
	}
	// fallback: return first valid
	for _, ip := range ips {
		if ip != nil { return ip }
	}
	return nil
}

func stripPort(s string) string {
	if i := strings.LastIndex(s, ":"); i != -1 {
		// could be IPv6; only strip port if there's only one ':' after removing brackets
		if strings.HasPrefix(s, "[") && strings.Contains(s, "]:") {
			if idx := strings.Index(s, "]"); idx != -1 {
				return s[1:idx]
			}
		}
		if strings.Count(s, ":") == 1 {
			return s[:i]
		}
	}
	return s
}

