package proxyconfig

import (
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// The below is an excerpt from net/http/httpproxy that they do not export
type proxyMatchers struct {
	ipMatchers     []matcher
	domainMatchers []matcher
}

func (m *proxyMatchers) matches(addr string) bool {
	if len(addr) == 0 {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() {
			return true
		}
	}

	addr = strings.ToLower(strings.TrimSpace(host))

	if ip != nil {
		for _, m := range m.ipMatchers {
			if m.match(addr, port, ip) {
				return true
			}
		}
	}
	for _, m := range m.domainMatchers {
		if m.match(addr, port, ip) {
			return true
		}
	}
	return false
}

func parseNoProxy(noProxyConfig string) *proxyMatchers {
	matchers := &proxyMatchers{}

	for _, p := range strings.Split(noProxyConfig, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}

		if p == "*" {
			matchers.ipMatchers = []matcher{allMatch{}}
			matchers.domainMatchers = []matcher{allMatch{}}
			return matchers
		}

		// IPv4/CIDR, IPv6/CIDR
		if _, pnet, err := net.ParseCIDR(p); err == nil {
			matchers.ipMatchers = append(matchers.ipMatchers, cidrMatch{cidr: pnet})
			continue
		}

		// IPv4:port, [IPv6]:port
		phost, pport, err := net.SplitHostPort(p)
		if err == nil {
			if len(phost) == 0 {
				// There is no host part, likely the entry is malformed; ignore.
				continue
			}
			if phost[0] == '[' && phost[len(phost)-1] == ']' {
				phost = phost[1 : len(phost)-1]
			}
		} else {
			phost = p
		}
		// IPv4, IPv6
		if pip := net.ParseIP(phost); pip != nil {
			matchers.ipMatchers = append(matchers.ipMatchers, ipMatch{ip: pip, port: pport})
			continue
		}

		if len(phost) == 0 {
			// There is no host part, likely the entry is malformed; ignore.
			continue
		}

		// domain.com or domain.com:80
		// foo.com matches bar.foo.com
		// .domain.com or .domain.com:port
		// *.domain.com or *.domain.com:port
		if strings.HasPrefix(phost, "*.") {
			phost = phost[1:]
		}
		matchHost := false
		if phost[0] != '.' {
			matchHost = true
			phost = "." + phost
		}
		matchers.domainMatchers = append(matchers.domainMatchers, domainMatch{host: phost, port: pport, matchHost: matchHost})
	}

	return matchers
}

// matcher represents the matching rule for a given value in the NO_PROXY list
type matcher interface {
	// match returns true if the host and optional port or ip and optional port
	// are allowed
	match(host, port string, ip net.IP) bool
}

// allMatch matches on all possible inputs
type allMatch struct{}

func (a allMatch) match(host, port string, ip net.IP) bool {
	return true
}

type cidrMatch struct {
	cidr *net.IPNet
}

func (m cidrMatch) match(host, port string, ip net.IP) bool {
	return m.cidr.Contains(ip)
}

type ipMatch struct {
	ip   net.IP
	port string
}

func (m ipMatch) match(host, port string, ip net.IP) bool {
	if m.ip.Equal(ip) {
		return m.port == "" || m.port == port
	}
	return false
}

type domainMatch struct {
	host string
	port string

	matchHost bool
}

func (m domainMatch) match(host, port string, ip net.IP) bool {
	if strings.HasSuffix(host, m.host) || (m.matchHost && host == m.host[1:]) {
		return m.port == "" || m.port == port
	}
	return false
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

var portMap map[string]string = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if isASCII(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
