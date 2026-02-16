WhatsMyIP — compact containerized service

Quick start

Build locally (with Podman):

```sh
make podman
```

Run container:

```sh
podman run --rm -p 8080:8080 whatsmyip:latest
```

Or run directly (local binary):

```sh
./bin/whatsmyip --addr :8080
```

Endpoints
- GET / -> HTML page with IP
- GET /ip -> plaintext IP
- GET /json -> JSON {"ip":"x.x.x.x"}
- GET /healthz -> liveness (returns 200 OK)

Healthcheck
- The container image includes a Docker `HEALTHCHECK` that runs the binary with `--healthcheck`.
- Locally you can run the healthcheck mode which probes `http://127.0.0.1:8080/healthz` and exits 0/1:

```sh
./bin/whatsmyip --healthcheck
```

Configuration flags
- `--addr` listen address (default `:8080`)
- `--trusted-proxies` comma-separated CIDRs or IPs to trust for forwarding headers (e.g. `10.0.0.0/8,127.0.0.1`)
- `--rate-limit-per-min` requests per minute per client IP (default `60`)
- `--verbose` enable verbose internal logging (useful for debugging header parsing)
- `--rate-limit-burst` token-bucket burst size (requests allowed immediately)
- `--rate-limit-whitelist` comma-separated CIDRs or IPs that bypass rate limiting


Trusted proxies
- For secure and correct client IP detection, set `--trusted-proxies` to the CIDRs of your internal proxies/load-balancers. The server will only honor `Forwarded`, `X-Forwarded-For`, and related headers when the immediate peer is in that set.

Rate limiting
- The service includes a per-client token-bucket rate limiter. Configure rate using `--rate-limit-per-min` and `--rate-limit-burst`.
- Responses include `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers. Exceeded requests return HTTP 429 with a `Retry-After` header.
- To exempt internal systems, set `--rate-limit-whitelist` with CIDRs or IPs that should bypass rate limiting.

Build notes
- The `Dockerfile` builds a static Go binary (CGO disabled) and produces a minimal final image based on `scratch`.
- Use `make podman` or `podman build -t whatsmyip:latest .` to build with Podman.

Testing
- Unit tests live in `internal/ip/ip_test.go`. Run `go test ./...` locally.

Kubernetes / Compose
- Example manifests are provided in `k8s/` and `docker-compose.yml`. Configure `trustedProxies` via the container `--trusted-proxies` argument when deploying behind an ingress or proxy.

Admin / observability
- The service exposes a simple authenticated admin endpoint to inspect the in-memory rate-limit counters.

Admin endpoint: `/admin/ratelimit`
- Method: `GET`
- Authentication: Bearer token via `Authorization: Bearer <token>`.
- Enable by supplying `--admin-token` when starting the server (example: `--admin-token secret`). If `--admin-token` is empty the endpoint will reject requests.

Example request

```sh
curl -H "Authorization: Bearer secret" http://localhost:8080/admin/ratelimit
```

Example response (JSON)

```json
{
	"1.2.3.4": { "tokens": 3.5, "last": 1670000000 },
	"::1":   { "tokens": 2,   "last": 1670000050 }
}
```

- `tokens`: current token-bucket tokens (float). Higher means more immediate requests are allowed.
- `last`: unix timestamp of last update for that bucket.

Resetting counters
- You can clear rate-limit buckets via POST `/admin/ratelimit/reset`.
- Provide the admin token in `Authorization: Bearer <token>` header.
- If no body is provided the endpoint clears all buckets. To clear specific IPs send JSON body: `{ "ips": ["1.2.3.4", "::1"] }`.

Example (clear all):

```sh
curl -X POST -H "Authorization: Bearer secret" http://localhost:8080/admin/ratelimit/reset -v
```

Example (clear specific ips):

```sh
curl -X POST -H "Authorization: Bearer secret" -H "Content-Type: application/json" \
	-d '{"ips":["1.2.3.4","::1"]}' http://localhost:8080/admin/ratelimit/reset -v
```

**Metrics**

- The server exposes Prometheus metrics at `GET /metrics`.
- Exposed metrics include:
	- `whatsmyip_requests_total` — total number of requests (counter).
	- `whatsmyip_request_duration_seconds` — request duration histogram.
	- `whatsmyip_rate_limited_total` — number of requests rejected with 429 (counter).
	- `whatsmyip_bucket_tokens` — gauge with label `ip` showing current token count per client IP.
- Notes: metrics are in-memory and ephemeral; the `ip` label contains client IPs (possible PII). Do not expose `/metrics` publicly. Use Prometheus `metric_relabel_configs` to drop or obfuscate the `ip` label before storing metrics long-term.

Example Prometheus scrape config (drops the `ip` label on ingest):

```yaml
scrape_configs:
	- job_name: 'whatsmyip'
		static_configs:
			- targets: ['whatsmyip:8080']
		metrics_path: /metrics
		metric_relabel_configs:
			- action: labeldrop
				regex: ip
```

- Admin resets: POST `/admin/ratelimit/reset` also clears per-IP gauge labels to avoid stale metrics.

Security and best practices
- Treat the admin token as sensitive: inject via secret management (Kubernetes Secret, Podman/Docker secret, or environment protected by your orchestration).
- Do not expose admin endpoints publicly. Prefer restricting access to a management network or placing behind an authenticated reverse proxy.
- The admin view is read-only. If you need reset/clear operations, add an authenticated endpoint behind secure controls.

Security notes
- Do not trust forwarding headers unless you explicitly configure trusted proxies. Default behavior is to ignore headers from untrusted peers.

License / Attribution
- Lightweight implementation inspired by common public IP services (ipify, icanhazip, ifconfig.co) but implemented here for internal use.
