package ip

import (
    "net/http/httptest"
    "testing"
)

func TestDeriveClientIP(t *testing.T) {
    SetVerbose(false)

    tests := []struct{
        name string
        trusted []string
        remote string
        headers map[string]string
        want string
    }{
        {
            name: "no trusted ignores headers",
            trusted: nil,
            remote: "10.0.0.5:1234",
            headers: map[string]string{"X-Forwarded-For": "203.0.113.5"},
            want: "10.0.0.5",
        },
        {
            name: "trusted uses xff client",
            trusted: []string{"10.0.0.0/8"},
            remote: "10.0.0.1:4321",
            headers: map[string]string{"X-Forwarded-For": "203.0.113.5"},
            want: "203.0.113.5",
        },
        {
            name: "xff chain trims trailing trusted",
            trusted: []string{"10.0.0.0/8"},
            remote: "10.0.0.2:1111",
            headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 10.0.0.3"},
            want: "1.2.3.4",
        },
        {
            name: "forwarded header for tokens",
            trusted: []string{"127.0.0.0/8"},
            remote: "127.0.0.1:9999",
            headers: map[string]string{"Forwarded": `for="203.0.113.9";for=127.0.0.1`},
            want: "203.0.113.9",
        },
        {
            name: "malformed token ignored falls back to remote",
            trusted: []string{"127.0.0.0/8"},
            remote: "127.0.0.1:2222",
            headers: map[string]string{"X-Forwarded-For": `"notanip", 127.0.0.1`},
            want: "127.0.0.1",
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            // configure trusted
            if err := SetTrustedCIDRs(tc.trusted); err != nil {
                t.Fatalf("SetTrustedCIDRs failed: %v", err)
            }
            req := httptest.NewRequest("GET", "http://example.test/", nil)
            req.RemoteAddr = tc.remote
            for k, v := range tc.headers {
                req.Header.Set(k, v)
            }
            got := DeriveClientIP(req)
            if got != tc.want {
                t.Fatalf("DeriveClientIP = %q, want %q", got, tc.want)
            }
        })
    }
}

func TestWhitelistCIDRs(t *testing.T) {
    // configure whitelist
    if err := SetWhitelistCIDRs([]string{"192.0.2.0/24", "2001:db8::/32", "203.0.113.5"}); err != nil {
        t.Fatalf("SetWhitelistCIDRs failed: %v", err)
    }

    tests := []struct{
        ip string
        want bool
    }{
        {"192.0.2.1", true},      // inside 192.0.2.0/24
        {"192.0.3.1", false},     // outside
        {"203.0.113.5", true},    // exact IP entry
        {"2001:db8::1", true},    // inside IPv6 range
        {"2001:db9::1", false},   // outside IPv6 range
        {"::1", false},           // not whitelisted
    }

    for _, tc := range tests {
        got := IsWhitelisted(tc.ip)
        if got != tc.want {
            t.Fatalf("IsWhitelisted(%q) = %v, want %v", tc.ip, got, tc.want)
        }
    }
}
