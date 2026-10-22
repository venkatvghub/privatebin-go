# Design notes

Deliberate behaviour the reviewer cannot see in a diff. Read from the base branch.

- **Errors are HTTP 200 with `{"status":1,"message":...}`.** PrivateBin's JSON API does this and existing clients depend on it. Only the optional login gate returns HTTP 401. Flag if a change alters status codes for the PrivateBin endpoints (`POST /`, `GET /?<id>`, delete by token).
- **No accounts, no owner on pastes.** The delete token is HMAC-SHA256(salt, id) and is the only ownership proof. Flag if a change stores user identity next to a paste.
- **The burn flag lives in `adata[3]`, not a column.** This matches the PrivateBin 2.1.0 schema. Flag if a change adds columns to `paste`, `comment` or `config`; the extra `expiredate` index is the one allowed addition.
- **Reading a burn paste goes through `Service.Read` and `Take`.** `Take` is one atomic `DELETE ... RETURNING`; of concurrent readers exactly one wins. Covered by `TestTakeIsAtomic`. Flag if burn handling stops going through `Take`.
- **Discussions are not supported.** The `comment` table exists for schema compatibility only; comment requests return `status: 1`.
- **Client IP is the TCP peer unless `TRUSTED_PROXIES` is set.** Flag any use of `X-Forwarded-For` that bypasses `c.ClientIP()`.
- **`/metrics` is served on the app port, unauthenticated, when `METRICS_ENABLED` is true (the default).** Operators restrict it at their proxy. It must expose only route templates, methods, status codes and counters. Flag if a metric label or value ever carries a paste id, token, IP or request content.
