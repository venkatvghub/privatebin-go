# privatebin-go

Zero-knowledge pastebin. Text is encrypted in the browser with AES-256-GCM; the key lives only in the URL fragment (`#...`), which browsers never send to a server. The server stores ciphertext and cannot read it.

Single Go binary (Gin) with the web UI embedded, backed by PostgreSQL (GORM v2). The JSON API and SQL schema are compatible with [PrivateBin](https://github.com/PrivateBin/PrivateBin) 2.x, so existing PrivateBin clients and databases keep working.

## Features

- Client-side encryption (WebCrypto: PBKDF2-SHA256 key derivation, AES-256-GCM, optional deflate compression, optional password)
- Expiry: 5 min, 10 min, 1 hour, 1 day, 1 week, 1 month, 1 year, never
- Burn after reading, destroyed atomically on first read (confirmation click first, so link previews cannot burn it)
- Delete links (HMAC delete tokens)
- Plain text, Markdown and syntax-highlighted views, rendered client side (marked, DOMPurify, highlight.js; all self-hosted)
- PrivateBin v2 JSON API plus OpenAPI/Swagger at `/swagger/` (`/openapi.yaml`)
- Structured JSON logs (zap) and Prometheus metrics
- Strict CSP, HSTS, no-referrer, per-IP rate limit, request size limit
- Optional login (OIDC via Dex) restricting who can create pastes; reading stays anonymous
- Light and dark theme

Not supported: discussions/comments (the table exists, requests return `status: 1`), attachments, server-side search or code execution (impossible on ciphertext).

### What the server can see

Paste id, ciphertext size, creation and expiry time, whether it is burn-after-reading, and client IP at the network layer (not logged by the app). It cannot see content or key. As with any web-delivered crypto, a compromised server could serve malicious JavaScript: run behind HTTPS and keep the CSP.

## Quick start

```bash
cp .env.example .env        # edit DELETE_SALT (32+ chars) at least
docker compose up -d --build
```

- App and UI: http://localhost:8080
- Swagger UI: http://localhost:8080/swagger/
- Metrics: http://localhost:9090/metrics
- Health: http://localhost:8080/healthz

`docker compose` runs two containers: `app` (frontend and backend in one image) and `db` (Postgres 16). Optional login adds Dex: `docker compose --profile auth up -d --build` with `AUTH_ENABLED=true` (dev user `dev@example.com` / `password`, see `dex/config.yaml`).

## Configuration

Read from environment variables; a `.env` file (gitignored) is loaded if present and real environment variables win. See `.env.example`.

| Variable | Default | Purpose |
|---|---|---|
| `APP_NAME` | required | added as `app` to every log line |
| `DATABASE_URL` | required | Postgres DSN |
| `DELETE_SALT` | required, 32+ chars | HMAC key for delete tokens; set equal to PrivateBin's server salt to honour its tokens |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `METRICS_ADDR` | `:9090` | Prometheus listener; empty disables |
| `LOG_LEVEL` | `info` | zap level |
| `BASE_URL` | `http://localhost:8080` | used for the OIDC redirect |
| `MAX_PASTE_BYTES` | `2097152` | request body limit |
| `TABLE_PREFIX` | empty | table prefix (PrivateBin `tbl` option) |
| `SWAGGER_ENABLED` | `true` | serve `/swagger/` and `/openapi.yaml` |
| `AUTH_ENABLED` | `false` | require OIDC login to create pastes |
| `TRUSTED_PROXIES` | empty | comma separated proxy IPs/CIDRs whose `X-Forwarded-For` is trusted. Leave empty unless behind a reverse proxy, otherwise the per-IP rate limit can be spoofed |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `SESSION_SECRET` | | needed when `AUTH_ENABLED=true` (`SESSION_SECRET` 32+ chars). Cookies are `Secure` when `BASE_URL` starts with `https://` |

## API

PrivateBin JSON API (send `X-Requested-With: JSONHttpRequest`). Errors are HTTP 200 with `{"status":1,"message":...}`, as in PrivateBin.

```bash
# create
curl -H 'X-Requested-With: JSONHttpRequest' -H 'Content-Type: application/json' \
  -d '{"v":2,"adata":[[...],"plaintext",0,0],"ct":"...","meta":{"expire":"1week"}}' http://localhost:8080/
# read      GET /?<id>   or   GET /?pasteid=<id>
# delete    GET /?pasteid=<id>&deletetoken=<token>
```

Full contract: `web/openapi.yaml` (served at `/openapi.yaml`). Extensions beyond PrivateBin: `GET /api/config`, `GET /api/paste/{id}/meta`, `/healthz`, and with `AUTH_ENABLED=true` HTTP 401 on unauthenticated create.

## Database

Tables `paste`, `comment`, `config` are created with the same DDL PrivateBin 2.1.0 uses on PostgreSQL (existing tables are left untouched):

```
paste(dataid CHAR(16) PK, data TEXT, expiredate INT, meta TEXT)
comment(dataid, pasteid, parentid, data, vizhash, postdate)
config(id CHAR(16) PK, value TEXT)    -- VERSION row
```

## Security

Checked against the OWASP Top 10 (2021); see `SECURITY.md` for the review and how to report issues. `make audit` runs `govulncheck` and `gosec`.

## Building

Requires Go (see `go.mod`) and Docker. Generate secrets with `openssl rand -hex 32`; the app refuses to start with the `.env.example` placeholders.

```bash
go build -o privatebin-go ./cmd/privatebin-go     # needs DATABASE_URL, APP_NAME, DELETE_SALT
make run                               # go run ./cmd/privatebin-go
docker build -t privatebin-go .              # Chainguard go -> Chainguard static, non-root
```

## Testing

```bash
go vet ./...
go test ./...                          # DB tests skip unless TEST_DATABASE_URL is set
# with the compose database (port is not published; run inside the network):
docker run --rm --network privatebin-go_default -v "$PWD":/src -w /src \
  -e TEST_DATABASE_URL='postgres://privatebin:privatebin@db:5432/privatebin?sslmode=disable' \
  cgr.dev/chainguard/go:latest test ./...
make deadcode                          # golang.org/x/tools deadcode
make audit                             # govulncheck + gosec
```

## Contributing

1. Fork and create a branch.
2. Keep the PrivateBin wire format and SQL schema unchanged; do not add server-side features that need plaintext.
3. Add or update tests; run `go vet ./...`, `go test ./...` and `make deadcode`.
4. Frontend: no inline scripts or styles (the CSP forbids them), no CDN assets; vendored libraries live in `web/vendor/` with their own licences.
5. Update `web/openapi.yaml` when the API changes.
6. Open a pull request describing the change and how you tested it.

Report bugs and request features through the issue templates in `.github/ISSUE_TEMPLATE/`. For security issues, open a private report rather than a public issue.

## Credits and licence

The API and storage format are compatible with [PrivateBin](https://github.com/PrivateBin/PrivateBin); the code, UI and crypto are an independent implementation. Licensed under the MIT License, see `LICENSE`.
