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

Use Nix for local dependencies. The flake provides Rust 1.95, protobuf, OpenSSL, Docker Compose, Bats, PostgreSQL tools, cargo-audit, and typos.

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
| `make audit` | Run `cargo audit` |

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
nix develop -c make start
```

The local stack uses:

- Postgres 17 from `docker-compose.yml`.
- `LNURL_DB_URL=postgres://user:password@127.0.0.1:5432/lnurl`.
- `LNURL_DOMAINS=localhost:8080,127.0.0.1:8080`.
- `LNURL_NETWORK=regtest`.
- `LNURL_SCHEME=http`.

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
  -e LNURL_ADDRESS="0.0.0.0:8080" \
  -e LNURL_AUTO_MIGRATE="true" \
  -e LNURL_DB_URL="postgres://user:password@postgres_host:5432/lnurl" \
  -e LNURL_DOMAINS="yourdomain.com" \
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

The server is configured in this precedence order:

1. Command-line arguments.
2. Environment variables prefixed with `LNURL_`.
3. TOML config file.

Example `lnurl.conf`:

```toml
address = "0.0.0.0:8080"
auto_migrate = true
db_url = "postgres://user:password@localhost:5432/lnurl"
domains = "yourdomain.com"
log_level = "info"
max_sendable = 4000000000
min_sendable = 1000
network = "mainnet"
scheme = "https"
```

Important options:

| Option | Description | Default |
|--------|-------------|---------|
| `--address` | Address the server listens on | `0.0.0.0:8080` |
| `--auto-migrate` | Automatically apply database migrations | `false` |
| `--db-url` | PostgreSQL or SQLite connection string | `""` |
| `--domains` | Comma-separated allowed domains | `localhost:8080` |
| `--log-level` | `RUST_LOG` style filter | `info` |
| `--network` | Spark network: `mainnet`, `testnet`, or `regtest` | `mainnet` |
| `--scheme` | Scheme used in generated LNURL callback URLs | `https` |
| `--min-sendable` | Minimum payment amount in millisatoshi | `1000` |
| `--max-sendable` | Maximum payment amount in millisatoshi | `4000000000` |
| `--webhook-domain` | Domain used when registering the Spark SSP webhook URL | unset |
| `--ssp-auth-seed` | Hex-encoded 32-byte seed for Spark SSP authentication | random |

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
      LNURL_ADDRESS: "0.0.0.0:8080"
      LNURL_AUTO_MIGRATE: "true"
      LNURL_DB_URL: "postgres://user:password@postgres:5432/lnurl"
      LNURL_DOMAINS: "localhost:8080,127.0.0.1:8080"
      LNURL_NETWORK: "regtest"
      LNURL_SCHEME: "http"
    ports:
      - "8080:8080"
    depends_on:
      - postgres
```
