<!-- generated-by: gsd-doc-writer -->
# Testing

This project uses Rust's built-in test harness for unit and integration-style tests, Tokio for async tests, Wiremock for mocked Blink GraphQL client tests, and Bats for end-to-end HTTP protocol coverage.

## Test Framework and Setup

| Layer | Framework/tool | Version/source | Setup |
|---|---|---|---|
| Rust unit and integration-style tests | Rust built-in test harness with `#[test]` and `#[tokio::test]` | Rust `stable` from `rust-toolchain.toml`; Tokio `1.45.1` in `Cargo.toml` | Run from a shell with the Rust toolchain installed. `nix develop` provides the pinned toolchain and native dependencies. |
| Blink GraphQL client tests | Wiremock | `wiremock = "0.6.5"` in `crates/blink-client/Cargo.toml` | Included through Cargo dev-dependencies. Tests use local mock servers, not live Blink services. |
| End-to-end protocol tests | Bats | `1.13.0` in `flake.nix` | Run from `nix develop` so `bats`, Docker, Docker Compose, `jq`, `curl`, and `openssl` are available. |

Before running tests locally:

```bash
nix develop
cargo build --locked --all-targets
```

PostgreSQL-backed tests and Bats E2E tests require Docker because `docker-compose.yml` starts PostgreSQL 17. The E2E helper also starts the `lnurl-server` binary and waits for `/health` before running protocol checks.

## Running Tests

Run the full Rust test suite without PostgreSQL integration tests:

```bash
make test-rust
```

This executes:

```bash
env -u LNURL_TEST_POSTGRES_URL cargo test --locked
```

Run PostgreSQL integration tests:

```bash
make test-integration
```

This starts PostgreSQL through Docker Compose and runs:

```bash
LNURL_TEST_POSTGRES_URL=postgres://user:password@127.0.0.1:${LNURL_POSTGRES_PORT:-25432}/lnurl cargo test --locked postgres_tests -- --test-threads=1
```

Run all Bats E2E tests:

```bash
make test-e2e
```

The target builds `lnurl-server`, `e2e_auth`, `blink_graphql_mock`, and `e2e_zap_request`, then runs:

```bash
LNURL_POSTGRES_PORT=${LNURL_POSTGRES_PORT:-25432} bats -t bats
```

Run the release test gate used by maintainers:

```bash
make release-check
```

This runs formatting and Clippy checks, Rust tests, PostgreSQL integration tests, E2E tests, and `cargo audit`.

Useful focused commands:

```bash
cargo test --locked lnurl_pay
cargo test --locked postgres_tests -- --test-threads=1
cargo test --locked -p blink-client --test client
bats -t bats/auth_endpoints.bats
bats -t bats/lnurl_protocol.bats
bats -t bats/blink_mocked_e2e.bats
```

## Writing New Tests

Rust tests are usually co-located with the module they exercise under `#[cfg(test)] mod tests`. Use this pattern for route handlers, services, repository behavior, webhook delivery, zap receipts, and helpers. Existing examples include:

- `src/routes/lnurl_pay.rs` for LNURL discovery, callback, wallet modifier, and protocol response tests.
- `src/routes/webhook.rs` for Spark SSP and Blink settlement webhook behavior.
- `src/routes/internal.rs` and `src/routes/account.rs` for internal API behavior.
- `src/invoice_paid.rs`, `src/webhook_notify.rs`, `src/webhooks/background.rs`, and `src/zap.rs` for service and background-worker behavior.
- `crates/blink-client/tests/client.rs` for Wiremock-backed Blink GraphQL request and response coverage.

Repository parity tests live in shared test modules and are called by both SQLite and PostgreSQL test modules. When adding persistence behavior, update both backend implementations and extend the shared tests in `src/repository.rs`, `src/webhooks/repository.rs`, or the owning service module.

For route tests, reuse `src/routes/test_support.rs`; it provides the mock repository, Axum test helpers, signed JWT helpers, and provider stubs used by co-located route tests.

For externally visible behavior, add or update Bats coverage in `bats/`:

- `bats/auth_endpoints.bats` covers authenticated Spark-compatible management endpoints and internal transfer flows.
- `bats/lnurl_protocol.bats` covers LNURL discovery, callbacks, verification, zap behavior, and webhook side effects.
- `bats/blink_mocked_e2e.bats` covers Blink-backed flows through the checked-in GraphQL mock.

Bats helpers are in `bats/helpers/common.bash` and `bats/helpers/assertions.bash`. The local stack helper is `scripts/start-local-stack.sh`.

## Coverage Requirements

No coverage threshold is configured.

| Type | Threshold |
|---|---:|
| Lines | Not configured |
| Branches | Not configured |
| Functions | Not configured |
| Statements | Not configured |

There is no `cargo-llvm-cov`, `tarpaulin`, `grcov`, or coverage-threshold configuration in `Cargo.toml`, `Makefile`, or the checked-in CI pipeline. Use the existing Rust, repository parity, Wiremock, and Bats suites as the current quality gate.

## CI Integration

No GitHub Actions workflow files are present in this repository. CI is defined through the Concourse/ytt pipeline in `ci/pipeline.yml`.

The `blink-lnurl-server` pipeline group includes these test-related jobs:

| Job | Definition | Command |
|---|---|---|
| `check-code` | `rust_check_code()` in `ci/pipeline.yml`, implemented by `ci/vendor/tasks/rust-check-code.sh` | `nix develop -c make check-code` when Nix is available, otherwise `make check-code` |
| `integration-tests` | `run_on_nix_host("integration-tests", "make test-in-ci")` in `ci/pipeline.yml` | `make test-in-ci` |
| `e2e-tests` | `run_on_nix_host("e2e-tests", "make e2e")` in `ci/pipeline.yml` | `make e2e` |

`make test-in-ci` runs `make test-rust` followed by `make test-integration`. The release job waits for `integration-tests`, `e2e-tests`, and `check-code` to pass before release tasks proceed.
