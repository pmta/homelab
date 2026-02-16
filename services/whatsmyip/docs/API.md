API: whatsmyip

Endpoints

- GET / (text/html)
  - returns a simple HTML page displaying the client's IP. Server-side rendered.

- GET /ip (text/plain)
  - returns the client IP as plaintext, e.g. 203.0.113.5

- GET /json (application/json)
  - returns JSON object: {"ip":"203.0.113.5"}

- GET /healthz (text/plain)
  - returns 200 OK with body "ok"

Headers and behavior

- CORS: service sets Access-Control-Allow-Origin: * by default for simple cross-origin usage.
- Cache-Control: no-store
- Vary: Origin
- Rate limiting: default 60 requests/minute per client IP, returns 429 Too Many Requests with Retry-After when exceeded.

IP derivation rules

Precedence (best-effort): Forwarded (RFC7239) -> X-Forwarded-For (left-most entry) -> X-Real-IP -> CF-Connecting-IP -> RemoteAddr.

Important: Operators should deploy this service behind trusted proxies or a load balancer and configure network-level controls. By default the service does not validate headers against a trusted-proxies list in this minimal scaffold; implementers should enforce a `--trusted-proxies` CIDR list or similar to avoid header spoofing.
