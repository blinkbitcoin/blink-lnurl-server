# Getting Started

This guide gets a local Blink LNURL Server running with PostgreSQL and the Rust development toolchain.

## Prerequisites

- **Nix** with flakes enabled, or **direnv** using the repository `.envrc`, is the recommended way to install local tools.
- The Nix development shell provides Rust `stable`, `rust-analyzer`, `rust-src`, protobuf, OpenSSL, Docker, Docker Compose, PostgreSQL CLI tools, Bats `1.13.0`, `cargo-audit`, `typos`, `jq`, and `curl` from `flake.nix`.
- Docker must be running for the local PostgreSQL dependency. The checked-in `docker-compose.yml` uses `postgres:17`.
- If you do not use Nix, install the Rust stable toolchain from `rust-toolchain.toml`, Docker Compose, protobuf, OpenSSL, PostgreSQL CLI tools, Bats, `cargo-audit`, `typos`, `jq`, and `curl` yourself.

## Installation steps

1. Clone the repository:

   ```bash
   git clone git@github.com:blinkbitcoin/blink-lnurl-server.git
   ```

2. Enter the project directory:

   ```bash
   cd blink-lnurl-server
   ```

3. Enter the development environment:

   ```bash
   nix develop
   ```

   If you use direnv instead, run this once:

   ```bash
   direnv allow
   ```

4. Build all Rust targets with the lockfile enforced:

   ```bash
   make build
   ```

## First run

The direct host-run command below requires PostgreSQL to be reachable on `127.0.0.1:5432`; the checked-in `docker-compose.override.yml` publishes `${LNURL_POSTGRES_PORT:-5432}:5432` by default:

```bash
docker compose up -d postgres && \
LNURL_SSP_AUTH_SEED=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
cargo run --locked --bin lnurl-server -- \
  --address 127.0.0.1:8080 \
  --auto-migrate \
  --db-url postgres://user:password@127.0.0.1:5432/lnurl \
  --domains localhost:8080,127.0.0.1:8080 \
  --log-level info \
  --network regtest \
  --scheme http \
  --webhook-domain localhost:8080
```

In another shell, confirm the server is responding:

```bash
curl -fsS http://localhost:8080/health
```

Expected result: HTTP `200 OK` with an empty response body.

## Common setup issues

- **Docker is not running or PostgreSQL is not ready.** `docker compose up -d postgres` starts the `postgres:17` service. If the server cannot connect to `postgres://user:password@127.0.0.1:5432/lnurl`, check `docker compose ps` and wait for the `postgres` health check to pass.
- **Port `8080` is already in use, or PostgreSQL is not reachable.** Change `--address` for the server. If host port `5432` is already in use, set `LNURL_POSTGRES_PORT` before running Docker Compose and update the `--db-url` port to match.
- **Startup fails with `LNURL_WEBHOOK_DOMAIN is required to create Blink invoice webhookUrl callbacks`.** Pass `--webhook-domain localhost:8080` or set `LNURL_WEBHOOK_DOMAIN=localhost:8080`. The server uses it to build Blink callbacks at `{scheme}://{webhook_domain}/webhook/blink`.
- **Nix is unavailable.** Use the tool versions and packages listed in `flake.nix`, then run the same `make` and `cargo` commands without `nix develop`.

## Next steps

- Read [Configuration](CONFIGURATION.md) for all `LNURL_` environment variables and TOML config options.
- Read [Architecture](ARCHITECTURE.md) for the server components and data flow.
- Use `make test-rust`, `make test-integration`, or `make e2e` to validate changes locally.
