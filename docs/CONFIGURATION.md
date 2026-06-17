# Configuration

Blink LNURL Server is configured from command-line arguments, a TOML config file, and environment variables prefixed with `LNURL_`. The implementation merges values in this order: parsed command-line/default values, then the TOML config file, then `LNURL_` environment variables. The `--config` argument selects the TOML file path before the file is loaded; the default path is `lnurl.conf`.

## Environment variables

No `.env.example` or `.env.sample` file is present. The variables below are derived from the `Args` configuration struct in `src/main.rs` and the local Docker/Makefile setup.

`DEPLOYMENT_ENV` is the required deployment selector for provider runtime wiring. Supported values are `production`, `staging`, and `local`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEPLOYMENT_ENV` | **Required at startup** | unset | Selects runtime provider mapping: `production ->` Spark/LNURL `mainnet` + Blink production GraphQL, `staging ->` Spark/LNURL `regtest` + Blink signet behavior + staging GraphQL, `local ->` Spark/LNURL `regtest` + Blink local behavior. Spark staging intentionally stays on `regtest` for now. |

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LNURL_ADDRESS` | Optional | `0.0.0.0:8080` | Socket address the HTTP server binds to. |
| `LNURL_AUTO_MIGRATE` | Optional | `false` | When `true`, applies embedded PostgreSQL or SQLite migrations at startup. |
| `LNURL_DB_URL` | Required for persistent deployments | `""` | Database connection string. Values beginning with `postgres` use PostgreSQL; other values use SQLite. |
| `LNURL_LOG_LEVEL` | Optional | `info` | `tracing_subscriber` env-filter string for application logs. |
| `LNURL_NETWORK` | Legacy compatibility only | `mainnet` | Startup now derives the Spark/LNURL runtime network from `DEPLOYMENT_ENV`; keep this only while older config files are cleaned up. |
| `LNURL_SCHEME` | Optional | `https` | Scheme used when constructing LNURL callback and webhook URLs. |
| `LNURL_MIN_SENDABLE` | Optional | `1000` | Minimum LNURL payment amount in millisatoshi. |
| `LNURL_MAX_SENDABLE` | Optional | `4000000000` | Maximum LNURL payment amount in millisatoshi. |
| `LNURL_DOMAINS` | Optional | `localhost:8080` | Comma-separated allowed domains. Configured domains are inserted into the database on startup. |
| `LNURL_NSEC` | Optional | unset | Nostr private key used to sign NIP-57 zap receipts. If unset, zap requests are ignored. |
| `LNURL_CA_CERT` | Optional | unset | Base64-encoded DER CA certificate used to validate bearer client certificates for authenticated `/lnurlpay/...` routes. |
| `LNURL_CRL_URL` | Optional | unset | URL fetched at startup for a comma-separated certificate revocation list. |
| `LNURL_WEBHOOK_DOMAIN` | **Required at startup** | unset | Domain used to build Blink invoice callback URLs at `{scheme}://{webhook_domain}/webhook/blink`; also used for Spark SSP webhook registration at `{scheme}://{webhook_domain}/webhook`. |
| `LNURL_SSP_AUTH_SEED` | Optional | random seed | Hex-encoded 32-byte seed used for Spark SSP authentication. Invalid or wrong-length values log an error and fall back to a random seed. |
| `LNURL_WEBHOOK_DELIVERY_TTL_DAYS` | Optional | `90` | Number of days to retain webhook delivery rows before cleanup. |
| `LNURL_BLINK_GRAPHQL_ENDPOINT` | Optional | `https://api.blink.sv/graphql` | Blink GraphQL override path. Production and staging are pinned by `DEPLOYMENT_ENV`; local/test flows can still point this at a mock or local endpoint. |
| `LNURL_INTERNAL_JWKS_URL` | Optional | unset | URL to fetch Blink Core internal-auth JWKS from at startup. |
| `LNURL_INTERNAL_JWKS_PATH` | Optional | unset | Local path to read Blink Core internal-auth JWKS from at startup. Takes precedence over `LNURL_INTERNAL_JWKS_URL`. |
| `LNURL_INTERNAL_JWT_ISSUER` | Optional | unset | Expected issuer for RS256 internal-auth JWTs. Required, with an audience and JWKS source, for `/internal/...` routes to authorize requests. |
| `LNURL_INTERNAL_JWT_AUDIENCE` | Optional | unset | Expected audience for RS256 internal-auth JWTs. Required, with an issuer and JWKS source, for `/internal/...` routes to authorize requests. |
| `LNURL_CONFIG` | Optional | `lnurl.conf` | Mirrors the `config` field, but the TOML file path is resolved before environment variables are merged; use `--config` to select a non-default config file. |
| `LNURL_DEV_DONT_USE_LNURL_INCLUDE_SPARK_ADDRESS` | Optional, dev feature only | `false` | Development-only option compiled behind the `dev` Cargo feature to include Spark addresses in generated invoices. |
| `LNURL_TEST_POSTGRES_URL` | Test-only | unset | PostgreSQL URL used by tests named `postgres_tests`; not used by the runtime server. |
| `LNURL_POSTGRES_PORT` | Local tooling only | `5432` for `make start`, `25432` for some test targets | Port used by Docker Compose helper scripts and Makefile targets. |
| `LNURL_BIN` | Local tooling only | `target/debug/lnurl-server` | Binary path used by `scripts/start-local-stack.sh`. |

## Config file format

The server reads a TOML config file from `lnurl.conf` by default or from the path passed to `--config`. Keys use the Rust field names from `src/main.rs` in `snake_case`.

Minimal persistent local example:

```toml
address = "0.0.0.0:8080"
auto_migrate = true
db_url = "postgres://user:password@127.0.0.1:5432/lnurl"
domains = "localhost:8080,127.0.0.1:8080"
log_level = "info"
scheme = "http"
webhook_domain = "localhost:8080"
ssp_auth_seed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

Run that config with `DEPLOYMENT_ENV=local`. If Blink should hit a mock or other local GraphQL service, also set `LNURL_BLINK_GRAPHQL_ENDPOINT`.

Production-oriented example with internal auth enabled:

```toml
address = "0.0.0.0:8080"
auto_migrate = false
db_url = "postgres://user:password@postgres-host:5432/lnurl"
domains = "lnurl.example.com"
log_level = "info"
scheme = "https"
webhook_domain = "lnurl.example.com"
internal_jwks_url = "https://issuer.example.com/.well-known/jwks.json"
internal_jwt_issuer = "https://issuer.example.com/"
internal_jwt_audience = "lnurl-server"
```

Run that config with `DEPLOYMENT_ENV=production`.

## Required vs optional settings

Settings that can stop the server during startup:

- **`webhook_domain` / `LNURL_WEBHOOK_DOMAIN`**: startup returns `LNURL_WEBHOOK_DOMAIN is required to create Blink invoice webhookUrl callbacks` when this is unset.
- **`db_url` / `LNURL_DB_URL`**: an invalid or unreachable database URL causes pool creation to fail. Use PostgreSQL URLs beginning with `postgres` for PostgreSQL; any other connection string is treated as SQLite.
- **`DEPLOYMENT_ENV`**: startup fails closed unless the value is exactly `production`, `staging`, or `local`.
- **`address` / `LNURL_ADDRESS`**: the configured socket must be valid and bindable.
- **`ca_cert` / `LNURL_CA_CERT`**: if set, the value must be base64-encoded DER; invalid values fail startup.
- **`crl_url` / `LNURL_CRL_URL`**: if set, the server fetches it during startup; fetch or response-read failures fail startup.
- **`nsec` / `LNURL_NSEC`**: if set, it must parse as a Nostr private key.

Settings that fail closed or fall back instead of stopping the server:

- Internal auth is enabled only when issuer, audience, and either a JWKS path or URL are available and parse successfully. Otherwise `/internal/...` routes return unauthorized.
- `ssp_auth_seed` falls back to a random seed when omitted or invalid.
- `nsec` omitted means zap requests are ignored rather than signed.
- `ca_cert` omitted disables bearer certificate validation on the authenticated `/lnurlpay/...` route group.

## Defaults

| Setting | Default | Defined in |
|---------|---------|------------|
| `address` | `0.0.0.0:8080` | `src/main.rs` |
| `config` | `lnurl.conf` | `src/main.rs` |
| `auto_migrate` | `false` | `src/main.rs` |
| `db_url` | `""` | `src/main.rs` |
| `log_level` | `info` | `src/main.rs` |
| `network` | `mainnet` (legacy compatibility) | `src/main.rs` |
| `scheme` | `https` | `src/main.rs` |
| `min_sendable` | `1000` millisatoshi | `src/main.rs` |
| `max_sendable` | `4000000000` millisatoshi | `src/main.rs` |
| `domains` | `localhost:8080` | `src/main.rs` |
| `webhook_delivery_ttl_days` | `90` | `src/main.rs` |
| `blink_graphql_endpoint` | `https://api.blink.sv/graphql` | `src/main.rs`, `crates/blink-client/src/client.rs` |
| `ssp_auth_seed` | random 32-byte seed | `src/main.rs` |
| `include_spark_address` | `false` outside the `dev` feature | `src/main.rs` |

## Per-environment overrides

Use the same `LNURL_` variables in each environment and keep secrets out of checked-in files. The repository does not contain `.env.development`, `.env.production`, `.env.test`, `.env.example`, or `.env.sample` files.

Local development defaults are encoded in `docker-compose.yml` and `scripts/start-local-stack.sh`:

```bash
DEPLOYMENT_ENV=local
LNURL_ADDRESS=0.0.0.0:8080
LNURL_AUTO_MIGRATE=true
LNURL_DB_URL=postgres://user:password@postgres:5432/lnurl
LNURL_DOMAINS=localhost:8080,127.0.0.1:8080
LNURL_LOG_LEVEL=info
LNURL_SCHEME=http
LNURL_SSP_AUTH_SEED=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
LNURL_WEBHOOK_DOMAIN=localhost:8080
```

For production, set `DEPLOYMENT_ENV=production` plus platform secrets or environment variables for at least the database URL, allowed domains, scheme, webhook domain, Spark SSP seed, and internal-auth JWT/JWKS values if `/internal/...` routes are used. For staging, set `DEPLOYMENT_ENV=staging`; Spark still maps to `regtest` there intentionally until the later signet switch.
