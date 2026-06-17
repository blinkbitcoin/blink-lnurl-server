# Blink LNURL Server

Blink LNURL Server provides LNURL-pay and Lightning Address endpoints backed by Spark invoice creation.

## What It Does

The server lets a user register a username and Spark public key. After registration, the server can:

- Serve LNURL-pay metadata for `username@domain.com`.
- Create Spark Lightning invoices for that registered user.
- Serve Lightning Address discovery at `/.well-known/lnurlp/{username}`.
- Store invoice metadata for LUD-21 verification, sender comments, zaps, and webhook delivery.

Trust model: the user must trust the LNURL server and Spark Service Provider not to collude by sharing the preimage. The user must also trust the LNURL server to return invoices that pay the registered user.

## Development Environment

Use Nix for local dependencies. The flake provides stable Rust, protobuf, OpenSSL, Docker Compose, Bats, PostgreSQL tools, cargo-audit, and typos.

With direnv:

```shell
direnv allow
```

Without direnv, prefix commands with `nix develop -c`:

```shell
nix develop -c make build
```

## Common Commands

| Command | Description |
|---------|-------------|
| `make build` | Build all Rust targets with `Cargo.lock` enforced |
| `make check-code` | Run `cargo fmt --check` and clippy with warnings denied |
| `make test-rust` | Run Rust tests without the optional Postgres test URL |
| `make start-deps` | Start local Docker Compose dependencies |
| `make stop-deps` | Stop local Docker Compose dependencies |
| `make reset-deps` | Restart local Docker Compose dependencies |
| `make start` | Start Postgres and run the LNURL server locally |
| `make test-integration` | Run Postgres-backed Rust tests |
| `make e2e` | Run Bats end-to-end tests |
| `make release-check` | Run the full release gate: formatting, clippy, Rust tests, Postgres integration tests, mocked E2E tests, and dependency audit |
| `make audit` | Run `cargo audit` |

## Release Verification

Run the complete local release gate before claiming milestone readiness:

```shell
nix develop -c make release-check
```

`release-check` runs the standard gates in order: `make check-code`, `make test-rust`, `make test-integration`, `make test-e2e`, and `make audit`. Treat any failed, skipped, flaky, or infrastructure-blocked command as release-blocking until it is fixed or precisely documented with the command, exit status, and blocker.

## Mocked Blink E2E Posture

Blink E2E coverage is deterministic and must not call live Blink services or Blink quickstart. The local E2E stack points the server at the checked-in `blink_graphql_mock` binary through `LNURL_BLINK_GRAPHQL_ENDPOINT` (or the matching `blink_graphql_endpoint` configuration option) so GraphQL invoice creation and payment-status behavior are exercised against local fixtures only.

The mocked E2E setup documents environment variable names and local endpoints only; do not add private keys, service tokens, `.envrc` contents, or live Blink credentials to tests or docs.

## Build

Development build:

```shell
nix develop -c make build
```

Release build:

```shell
nix develop -c cargo build --release --locked --bin lnurl-server
```

The release binary is written to `target/release/lnurl-server`.

## Run Locally

Start the local Postgres dependency and LNURL server:

```shell
LNURL_BLINK_GRAPHQL_ENDPOINT=http://<your-local-blink>/graphql nix develop -c make start
```

The local stack uses:

- Postgres 17 from `docker-compose.yml`.
- `DEPLOYMENT_ENV=local`.
- `LNURL_DB_URL=postgres://user:password@127.0.0.1:5432/lnurl`.
- `LNURL_DOMAINS=localhost:8080,127.0.0.1:8080`.
- `LNURL_SCHEME=http`.

`DEPLOYMENT_ENV` drives provider runtime selection:

- `production` → Spark/LNURL `mainnet`, Blink production GraphQL.
- `staging` → Spark/LNURL `regtest`, Blink signet behavior with `https://api.staging.blink.sv/graphql`.
- `local` → Spark/LNURL `regtest`, Blink local behavior through the configured `LNURL_BLINK_GRAPHQL_ENDPOINT` override path.

Spark staging stays explicitly pinned to `regtest` for now so the later Spark `regtest -> signet` switch is a one-line startup mapping change.

Explicit overrides still win when needed: use `LNURL_SPARK_NETWORK` to override Spark/LNURL network defaults and `LNURL_BLINK_GRAPHQL_ENDPOINT` to override the Blink GraphQL URL. `DEPLOYMENT_ENV=local` requires `LNURL_BLINK_GRAPHQL_ENDPOINT` because this repo does not define one fixed local Blink service URL.

For Blink invoice callbacks during local runs, `scripts/start-local-stack.sh` defaults the webhook domain to `localhost:8080` so Blink invoices receive `http://localhost:8080/webhook/blink` callbacks. Override it with `LNURL_WEBHOOK_DOMAIN` when using a different local host or public tunnel.

`make start` also expects `LNURL_BLINK_GRAPHQL_ENDPOINT` to point at the Blink local or mock GraphQL endpoint for `DEPLOYMENT_ENV=local`.

Run end-to-end tests:

```shell
nix develop -c make e2e
```

## Docker

Build a static musl binary from source and copy it into an Ubuntu runtime image:

```shell
docker build -t blink-lnurl-server .
```

Run the source-built image:

```shell
docker run --rm -p 8080:8080 \
  -e DEPLOYMENT_ENV="production" \
  -e LNURL_ADDRESS="0.0.0.0:8080" \
  -e LNURL_AUTO_MIGRATE="true" \
  -e LNURL_DB_URL="postgres://user:password@postgres_host:5432/lnurl" \
  -e LNURL_DOMAINS="yourdomain.com" \
  -e LNURL_WEBHOOK_DOMAIN="yourdomain.com" \
  blink-lnurl-server
```

`Dockerfile.release` builds a minimal distroless runtime image from a prebuilt static `lnurl-server` binary in the Docker build context:

```shell
cp target/x86_64-unknown-linux-musl/release/lnurl-server ./lnurl-server
docker build \
  -f Dockerfile.release \
  --build-arg VERSION="v0.1.0" \
  -t blink-lnurl-server:v0.1.0 \
  .
rm ./lnurl-server
```

## Configuration

The server merges configuration in this order, with later sources overriding earlier ones:

1. Command-line argument defaults.
2. TOML config file.
3. Environment variables prefixed with `LNURL_`.

Example `lnurl.conf`:

```toml
address = "0.0.0.0:8080"
auto_migrate = true
db_url = "postgres://user:password@localhost:5432/lnurl"
domains = "yourdomain.com"
log_level = "info"
max_sendable = 4000000000
min_sendable = 1000
scheme = "https"
```

Set `DEPLOYMENT_ENV` in the process environment because runtime provider selection now comes from `production`, `staging`, or `local`.

Important options:

| Option | Description | Default |
|--------|-------------|---------|
| `--address` | Address the server listens on | `0.0.0.0:8080` |
| `--auto-migrate` | Automatically apply database migrations | `false` |
| `--db-url` | PostgreSQL or SQLite connection string | `""` |
| `--domains` | Comma-separated allowed domains | `localhost:8080` |
| `--log-level` | `RUST_LOG` style filter | `info` |
| `--scheme` | Scheme used in generated LNURL callback URLs | `https` |
| `--min-sendable` | Minimum payment amount in millisatoshi | `1000` |
| `--max-sendable` | Maximum payment amount in millisatoshi | `4000000000` |
| `--webhook-domain` | Domain used for provider webhook URLs. Required for Blink invoice callbacks; Blink invoice creation sends `{scheme}://{webhook-domain}/webhook/blink`. Also used when registering the Spark SSP webhook URL. | unset |
| `--ssp-auth-seed` | Hex-encoded 32-byte seed for Spark SSP authentication | random |

`DEPLOYMENT_ENV` is required at startup and accepts only `production`, `staging`, or `local`. It sets the default provider wiring. `LNURL_SPARK_NETWORK` and `LNURL_BLINK_GRAPHQL_ENDPOINT` are optional explicit overrides.

`LNURL_WEBHOOK_DOMAIN` is required when running the server with Blink invoice support. Blink invoice creation passes a callback URL of `{LNURL_SCHEME}://{LNURL_WEBHOOK_DOMAIN}/webhook/blink` to Blink GraphQL for both BTC and USD invoices. The Blink callback route accepts flat provider payloads at public `POST /webhook/blink`; it is separate from the Spark SSP webhook at `POST /webhook`.

For the complete list:

```shell
nix develop -c cargo run --locked --bin lnurl-server -- --help
```

## Database Backends

The server chooses the database implementation from `db_url`:

- PostgreSQL: connection strings beginning with `postgres`.
- SQLite: any other connection string, for example `lnurl.sqlite`.

When `auto_migrate` is enabled, the server applies the embedded SQL migrations on startup.

## API Endpoints

Authenticated routes always require Spark signatures. If `ca_cert` is configured, authenticated routes also require a bearer certificate signed by that CA.

| Group | Method | Path | Description |
|-------|--------|------|-------------|
| Public LNURL | GET | `/.well-known/lnurlp/{identifier}` | LNURL-pay endpoint for Lightning Address handling |
| Public LNURL | GET | `/lnurlp/{identifier}` | Alternative LNURL-pay endpoint |
| Public LNURL | GET | `/lnurlp/{identifier}/invoice` | Invoice generation endpoint for LNURL-pay |
| Public | GET | `/verify/{payment_hash}` | LUD-21 invoice verification endpoint |
| Health | GET | `/health` | Health check endpoint |
| Webhook | POST | `/webhook` | Spark SSP payment notification webhook |
| Webhook | POST | `/webhook/blink` | Blink invoice status callback endpoint for flat `PAID` and `EXPIRED` payloads |
| Authenticated | GET | `/lnurlpay/available/{identifier}` | Check if a username is available |
| Authenticated | POST | `/lnurlpay/{pubkey}` | Register a username |
| Authenticated | DELETE | `/lnurlpay/{pubkey}` | Unregister a username |
| Authenticated | POST | `/lnurlpay/{pubkey}/transfer` | Transfer a username to another pubkey |
| Authenticated | POST | `/lnurlpay/{pubkey}/recover` | Recover a username registration |
| Authenticated | GET | `/lnurlpay/{pubkey}/metadata` | List LNURL sender comments, zaps, and invoice metadata |
| Authenticated | POST | `/lnurlpay/{pubkey}/metadata/{payment_hash}/zap` | Publish a zap receipt |
| Authenticated | POST | `/lnurlpay/{pubkey}/invoice-paid` | Notify a single paid invoice |
| Authenticated | POST | `/lnurlpay/{pubkey}/invoices-paid` | Notify paid invoices in batch |

## Docker Compose Example

```yaml
services:
  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: lnurl

  lnurl-server:
    build: .
    environment:
      DEPLOYMENT_ENV: "local"
      LNURL_ADDRESS: "0.0.0.0:8080"
      LNURL_AUTO_MIGRATE: "true"
      LNURL_BLINK_GRAPHQL_ENDPOINT: "http://your-local-blink/graphql"
      LNURL_DB_URL: "postgres://user:password@postgres:5432/lnurl"
      LNURL_DOMAINS: "localhost:8080,127.0.0.1:8080"
      LNURL_SCHEME: "http"
      LNURL_WEBHOOK_DOMAIN: "localhost:8080"
    ports:
      - "8080:8080"
    depends_on:
      - postgres
```

## Installation

Install the development toolchain and dependencies with Nix, then build the Rust binaries with Cargo through the project `Makefile`:

```bash
nix develop -c make build
```

If you use `direnv`, run `direnv allow` once and then use the same `make` targets without the `nix develop -c` prefix.

## Quick Start

1. Start the local PostgreSQL dependency and LNURL server:

   ```bash
   nix develop -c make start
   ```

2. Check that the server is responding:

   ```bash
   curl -fsS http://localhost:8080/health
   ```

3. Run the deterministic end-to-end suite against the local stack:

   ```bash
   nix develop -c make e2e
   ```

## Usage Examples

Check server health:

```bash
curl -i http://localhost:8080/health
```

Expected result: HTTP `200 OK`.

Fetch LNURL-pay metadata for a registered identifier:

```bash
curl -fsS \
  --header "Host: localhost:8080" \
  http://localhost:8080/.well-known/lnurlp/alice
```

Expected result: a JSON response with `tag: "payRequest"`, `minSendable`, `maxSendable`, `metadata`, `commentAllowed`, and a `callback` such as `http://localhost:8080/lnurlp/alice/invoice`.

Request an invoice from the LNURL callback:

```bash
curl -fsS \
  --header "Host: localhost:8080" \
  'http://localhost:8080/lnurlp/alice/invoice?amount=1000&comment=hello'
```

Expected result: a JSON response containing `pr`, `verify`, and an empty `routes` array, or an LNURL error response if the identifier is not registered or the amount is out of range.

## License

No license file or Cargo package license metadata is present in this repository.
