# Security

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab) rather than a public issue.

## Review against the OWASP Top 10 (2021)

Last reviewed with `govulncheck` (0 vulnerabilities), `gosec` (0 issues) and a manual pass.

| Risk | Status |
|---|---|
| A01 Broken access control | Delete tokens are HMAC-SHA256 of the id, compared in constant time. Ids are 64 random bits. Creating is optionally login-gated; POST needs the custom `X-Requested-With` header, which cross-site forms cannot send (CSRF). Metrics are bound to `127.0.0.1` in compose. |
| A02 Cryptographic failures | Content is encrypted in the browser (AES-256-GCM, PBKDF2-SHA256 with 600000 iterations, random IV and salt per paste, header authenticated as AAD). The key never leaves the URL fragment. Session cookies are signed and expiring (`securecookie`), `HttpOnly`, `SameSite=Lax`, `Secure` when `BASE_URL` is https. Terminate TLS in front of the app. |
| A03 Injection | All SQL goes through GORM with bound parameters. The only spliced value, `TABLE_PREFIX`, is validated against `^[A-Za-z0-9_]*$` in both config and `Migrate`. The UI renders text with `textContent`; Markdown is sanitised with DOMPurify. CSP forbids inline script and style outside the Swagger page. |
| A04 Insecure design | Body size limit, per-IP rate limit on create (client IP is the TCP peer unless `TRUSTED_PROXIES` is set, so `X-Forwarded-For` cannot be spoofed), PBKDF2 cost a paste may demand is capped at 10,000,000 (PrivateBin has no cap; this is the one deliberate deviation from its format checks), server read/write/idle timeouts. Burn-after-reading is an atomic delete. |
| A05 Security misconfiguration | Startup refuses placeholder or short secrets. Strict CSP, HSTS, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, CORP/COOP, `nosniff`. API responses are `no-store`. Gin runs in release mode. Container runs as non-root on a distroless-style Chainguard static image. Swagger can be disabled with `SWAGGER_ENABLED=false`. The Dex service and its static user are for development only. |
| A06 Vulnerable components | `go.mod` pins patched versions; CI runs `govulncheck` on every push and pull request; `make audit` runs it locally. Vendored front-end libraries are listed with SHA-256 sums in `web/vendor/CHECKSUMS.txt`. |
| A07 Authentication failures | OIDC authorisation-code flow with state, nonce and PKCE; the callback only redirects to `/`. The ID token is verified against the issuer. |
| A08 Integrity failures | No CDN or runtime-loaded code; everything is embedded in the binary. AES-GCM authenticates ciphertext and header. |
| A09 Logging and monitoring | JSON logs with route templates only: no bodies, query strings (delete tokens) or IPs. Prometheus metrics for requests, latency, creates and burns. Failed logins are not logged yet. |
| A10 SSRF | The only outbound request is OIDC discovery to the configured issuer. |

## Known limits

- As with any web-delivered end-to-end encryption, a compromised server could serve malicious JavaScript. Run over HTTPS and keep the CSP.
- The server sees paste size, timing, expiry and the burn flag.
- Pasting the same plaintext twice produces unrelated ciphertexts; there is no deduplication or content-based id.
