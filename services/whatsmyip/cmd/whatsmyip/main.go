package main

import (
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"io"
	"net/http"
	"os"
	"sync"
	"strconv"
	"strings"
	"time"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"whatsmyip/internal/ip"
)

var (
	addr          = flag.String("addr", ":8080", "listen address")
	trustedEnv    = flag.String("trusted-proxies", "", "comma-separated CIDR list of trusted proxies")
	rateLimitEnv   = flag.String("rate-limit-per-min", "60", "requests per minute per client IP")
	rateLimitBurst = flag.Int("rate-limit-burst", 10, "burst size for rate limiter (requests)")
	rateLimitWhitelist = flag.String("rate-limit-whitelist", "", "comma-separated CIDRs or IPs to bypass rate limiting")
	adminToken = flag.String("admin-token", "", "Bearer token required to access admin endpoints (optional)")
	verboseFlag   = flag.Bool("verbose", false, "enable verbose logging")
	healthcheckFlag = flag.Bool("healthcheck", false, "run healthcheck against local server and exit")
	tmpl          *template.Template
	staticDir     = "web"
)

func main() {
	flag.Parse()

	rl, err := strconv.Atoi(*rateLimitEnv)
	if err != nil || rl <= 0 {
		rl = 60
	}

	trusted := strings.TrimSpace(*trustedEnv)
	if trusted != "" {
		cidrs := strings.Split(trusted, ",")
		if err := ip.SetTrustedCIDRs(cidrs); err != nil {
			log.Fatalf("invalid trusted-proxies: %v", err)
		}
		log.Printf("trusted proxies set: %v", cidrs)
	}

	// set whitelist for rate limiting bypass
	wl := strings.TrimSpace(*rateLimitWhitelist)
	if wl != "" {
		cidrs := strings.Split(wl, ",")
		if err := ip.SetWhitelistCIDRs(cidrs); err != nil {
			log.Fatalf("invalid rate-limit-whitelist: %v", err)
		}
		log.Printf("rate-limit whitelist set: %v", cidrs)
	}

	ip.SetVerbose(*verboseFlag)

	var errt error
	tmpl, errt = template.ParseFiles(staticDir + "/index.html")
	if errt != nil {
		log.Fatalf("failed parse template: %v", errt)
	if *healthcheckFlag {
		// simple local health check against /healthz
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil {
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			os.Exit(0)
		}
		os.Exit(1)
	}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", makeHandler(indexHandler))
	mux.HandleFunc("/ip", makeHandler(ipHandler))
	mux.HandleFunc("/json", makeHandler(jsonHandler))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ok")) })
	mux.Handle("/metrics", promhttp.Handler())

	fs := http.FileServer(http.Dir(staticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// create rate limiter instance and middleware
	rlObj := newRateLimiter(rl, *rateLimitBurst)
	handler := rlObj.middleware(mux)

	// admin endpoints
	mux.HandleFunc("/admin/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if *adminToken == "" || token != *adminToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rlObj.Snapshot())
	})

	mux.HandleFunc("/admin/ratelimit/reset", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if *adminToken == "" || token != *adminToken {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// read optional JSON body: {"ips": ["1.2.3.4", "::1"]}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(b) == 0 {
			rlObj.ResetAll()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var payload struct{ Ips []string `json:"ips"` }
		if err := json.Unmarshal(b, &payload); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(payload.Ips) == 0 {
			rlObj.ResetAll()
		} else {
			rlObj.ResetIPs(payload.Ips)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("starting whatsmyip on %s", *addr)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Cache-Control", "no-store")
		fn(w, r)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := ip.DeriveClientIP(r)
	data := map[string]string{"IP": clientIP}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := ip.DeriveClientIP(r)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(clientIP))
}

func jsonHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := ip.DeriveClientIP(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ip": clientIP})
}

// token-bucket per-IP rate limiter. rate is requests per minute; burst is token bucket capacity.
func rateLimitMiddleware(perMin int, burst int) func(http.Handler) http.Handler {
	if perMin <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	ratePerSec := float64(perMin) / 60.0

	type bucket struct {
		tokens float64
		last   time.Time
	}

	m := map[string]*bucket{}
	var mu sync.Mutex

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := ip.DeriveClientIP(r)
			if clientIP == "" {
				clientIP = "unknown"
			}

			mu.Lock()
			b, ok := m[clientIP]
			if !ok {
				b = &bucket{tokens: float64(burst), last: time.Now()}
				m[clientIP] = b
			}
			now := time.Now()
			// refill
			elapsed := now.Sub(b.last).Seconds()
			if elapsed > 0 {
				b.tokens += elapsed * ratePerSec
				if b.tokens > float64(burst) {
					b.tokens = float64(burst)
				}
				b.last = now
			}

			// check token
			// if client IP is whitelisted, bypass rate limiting
			if ip.IsWhitelisted(clientIP) {
				mu.Unlock()
				next.ServeHTTP(w, r)
				return
			}

			if b.tokens >= 1.0 {
				b.tokens -= 1.0
				remaining := int(b.tokens)
				mu.Unlock()
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(perMin))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				next.ServeHTTP(w, r)
				return
			}

			// compute retry-after seconds (approx)
			need := 1.0 - b.tokens
			retrySec := int((need / ratePerSec) + 0.999)
			mu.Unlock()
			w.Header().Set("Retry-After", strconv.Itoa(retrySec))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		})
	}
}

type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter encapsulates token-bucket state and exposes middleware and snapshot.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	ratePerSec float64
	burst     int
}

// Prometheus metrics
var (
	promRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "whatsmyip_requests_total",
		Help: "Total HTTP requests received",
	})
	promRequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "whatsmyip_request_duration_seconds",
		Help:    "HTTP request durations in seconds",
		Buckets: prometheus.DefBuckets,
	})
	promRateLimited = promauto.NewCounter(prometheus.CounterOpts{
		Name: "whatsmyip_rate_limited_total",
		Help: "Total requests rate-limited",
	})
	promBucketTokens = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "whatsmyip_rate_limit_bucket_tokens",
		Help: "Current token-bucket tokens per client IP",
	}, []string{"ip"})
)

func newRateLimiter(perMin int, burst int) *rateLimiter {
	rl := &rateLimiter{
		buckets:   map[string]*bucket{},
		ratePerSec: float64(perMin) / 60.0,
		burst:     burst,
	}
	return rl
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		promRequests.Inc()

		// copy of previous middleware logic, but using rl struct
		clientIP := ip.DeriveClientIP(r)
		if clientIP == "" {
			clientIP = "unknown"
		}

		rl.mu.Lock()
		b, ok := rl.buckets[clientIP]
		if !ok {
			b = &bucket{tokens: float64(rl.burst), last: time.Now()}
			rl.buckets[clientIP] = b
		}
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * rl.ratePerSec
			if b.tokens > float64(rl.burst) {
				b.tokens = float64(rl.burst)
			}
			b.last = now
		}

		// whitelist bypass
		if ip.IsWhitelisted(clientIP) {
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		if b.tokens >= 1.0 {
			b.tokens -= 1.0
			remaining := int(b.tokens)
			// update prometheus gauge
			promBucketTokens.WithLabelValues(clientIP).Set(b.tokens)
			rl.mu.Unlock()
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(int(rl.ratePerSec*60)))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			next.ServeHTTP(w, r)
			promRequestDuration.Observe(time.Since(start).Seconds())
			return
		}

		need := 1.0 - b.tokens
		retrySec := 1
		if rl.ratePerSec > 0 {
			retrySec = int((need/rl.ratePerSec)+0.999)
		}
		// update prometheus that we rate-limited
		promRateLimited.Inc()
		rl.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retrySec))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		promRequestDuration.Observe(time.Since(start).Seconds())
	})
}

// Snapshot returns a copy of current buckets suitable for admin inspection.
func (rl *rateLimiter) Snapshot() map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for ipk, b := range rl.buckets {
		out[ipk] = map[string]interface{}{
			"tokens": b.tokens,
			"last":   b.last.Unix(),
		}
	}
	return out
}

// ResetAll clears all buckets.
func (rl *rateLimiter) ResetAll() {
	rl.mu.Lock()
	rl.buckets = map[string]*bucket{}
	rl.mu.Unlock()
	// clear gauge values
	promBucketTokens.Reset()
}

// ResetIPs removes specific IP buckets.
func (rl *rateLimiter) ResetIPs(ips []string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, ip := range ips {
		delete(rl.buckets, ip)
	}
	// remove from prometheus gauges
	for _, ip := range ips {
		promBucketTokens.DeleteLabelValues(ip)
	}
}
