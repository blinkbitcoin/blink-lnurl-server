# Development

## Local setup

Use the Nix development shell for the full local toolchain. `flake.nix` provides stable Rust from `rust-toolchain.toml`, `rust-analyzer`, `rust-src`, protobuf, OpenSSL, Docker, Docker Compose, PostgreSQL CLI tools, Bats, `cargo-audit`, `typos`, `curl`, and `jq`.

1. Fork the repository in GitHub, then clone your fork:

   ```bash
   git clone git@github.com:<your-org-or-user>/blink-lnurl-server.git
   cd blink-lnurl-server
   ```

2. Enter the development environment:

   ```bash
   nix develop
   ```

   If you use direnv, run:

   ```bash
   direnv allow
   ```

3. Build the Rust workspace:

   ```bash
   make build
   ```

4. Start the local PostgreSQL-backed server stack:

   ```bash
   make start
   ```

   `scripts/start-local-stack.sh` starts PostgreSQL with Docker Compose, builds `target/debug/lnurl-server` if needed, and runs the server on `127.0.0.1:8080` with regtest settings.

There is no `.env.example` file. Local defaults are encoded in `docker-compose.yml`, `docker-compose.override.yml`, and `scripts/start-local-stack.sh`. Do not commit local secrets or private environment files.

## Build commands

| Command | Description |
|---------|-------------|
| `make build` | Runs `cargo build --locked --all-targets` for the workspace. |
| `make check-code` | Runs `cargo fmt --all -- --check` and `cargo clippy --locked --all-targets -- -D warnings`. |
| `make audit` | Runs `cargo audit`. |
| `make test-rust` | Runs `env -u LNURL_TEST_POSTGRES_URL cargo test --locked` for Rust tests that do not require the optional Postgres test URL. |
| `make start-deps` | Starts the local PostgreSQL service with `docker compose up -d postgres`. |
| `make stop-deps` | Stops Docker Compose services with orphan cleanup. |
| `make reset-deps` | Restarts local Docker Compose dependencies by running `stop-deps` then `start-deps`. |
| `make start` | Runs `./scripts/start-local-stack.sh` to start PostgreSQL and the local LNURL server. |
| `make test-e2e` | Builds `lnurl-server`, `e2e_auth`, `blink_graphql_mock`, and `e2e_zap_request`, then runs Bats tests under `bats/`. |
| `make e2e` | Alias for `make test-e2e`. |
| `make test-integration` | Restarts Postgres on `LNURL_POSTGRES_PORT` and runs `cargo test --locked postgres_tests -- --test-threads=1` with `LNURL_TEST_POSTGRES_URL` set. |
| `make test-in-ci` | Runs `make test-rust` and `make test-integration`. |
| `make release-check` | Runs `check-code`, `test-rust`, `test-integration`, `test-e2e`, and `audit` in sequence. |

Useful direct Cargo commands:

```bash
cargo run --locked --bin lnurl-server -- --help
cargo build --release --locked --bin lnurl-server
```

## Code style

- **Rust formatting:** use `rustfmt` through `cargo fmt --all -- --check`; no custom `rustfmt.toml` is present, so the stable toolchain defaults apply.
- **Rust linting:** run `cargo clippy --locked --all-targets -- -D warnings` or `make check-code`. `Cargo.toml` enables Clippy lint groups for suspicious, complexity, perf, style, pedantic, and arithmetic-side-effect checks.
- **Spelling:** run `typos` when changing docs or user-facing strings. `typos.toml` excludes `CHANGELOG.md` and `*.cert`.
- **Shell scripts:** follow the existing script style in `scripts/start-local-stack.sh`: Bash, `set -euo pipefail`, and two-space indentation.
- **Bats tests:** follow the two-space test body style used in `bats/*.bats`.

The Concourse pipeline defines a `check-code` job in `ci/pipeline.yml`; the Rust check-code task runs `nix develop -c make check-code` when Nix is available.

## Branch conventions

The default branch is `main` (`ci/values.yml`). No formal branch naming rules are documented in this repository. Existing local branch names use short prefixes such as `feat/`, `ci-`, `docs/`, `chore/`, and `worktree-agent-`; prefer a descriptive branch name like `feat/blink-provider` or `docs/update-readme-docker`.

## PR process

No `CONTRIBUTING.md` or `.github/PULL_REQUEST_TEMPLATE.md` is present in this checkout; `.github/workflows/` contains `audit.yml`, `check-code.yml`, `spelling.yml`, `test-e2e.yml`, and `test-integration.yml`. Use the checked-in GitHub Actions workflows, Concourse pipeline, and Makefile gates as the source of truth:

- Keep changes focused and describe the behavior, tests, and migration impact in the pull request.
- Run `make check-code` before opening a PR.
- Run `make test-rust`; for database changes, also run `make test-integration`.
- Run `make e2e` when touching LNURL protocol behavior, authentication endpoints, Blink mocked GraphQL behavior, invoice settlement, zaps, or webhooks.
- Run `make release-check` before requesting release readiness or merging high-risk changes.
- For schema changes, update both `migrations/postgres/` and `migrations/sqlite/`, plus the matching repository implementations in `src/postgresql/` and `src/sqlite/`.
