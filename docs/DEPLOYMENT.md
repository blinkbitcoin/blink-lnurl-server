# Deployment

Blink LNURL Server deploys as the `lnurl-server` Rust binary, either built into a container image or released as a static Linux artifact. The service exposes HTTP on `LNURL_ADDRESS` and provides a readiness endpoint at `GET /health`.

## Deployment targets

| Target | Config file | Notes |
|--------|-------------|-------|
| Source-built Docker image | `Dockerfile` | Builds `lnurl-server` with `clux/muslrust:stable`, `cargo build --locked --release --bin lnurl-server`, and packages it in `ubuntu:24.04` as user `1000` with working directory `/lnurl`. |
| Distroless release image | `Dockerfile.release` | Copies a prebuilt static `lnurl-server` into `gcr.io/distroless/static` and accepts `VERSION`, `BUILDTIME`, and `COMMITHASH` build args. |
| Local Docker Compose stack | `docker-compose.yml`, `docker-compose.override.yml` | Runs PostgreSQL 17 plus the source-built server image on port `8080`; intended for local and test-like deployments, not a production manifest. |
| Concourse release pipeline | `ci/pipeline.yml`, `ci/values.yml` | Builds GitHub release artifacts, builds a Docker image with Kaniko, publishes it to `us.gcr.io/galoy-org/blink-lnurl-server`, then opens a chart update PR in `blinkbitcoin/charts`. |

## Build pipeline

The repository contains a Concourse/ytt pipeline in `ci/pipeline.yml` and GitHub Actions workflows under `.github/workflows/`.

Primary release flow:

1. `check-code`, `integration-tests`, and `e2e-tests` run before release jobs. The integration and E2E jobs call `make test-in-ci` and `make e2e` respectively.
2. The `release` job prepares release source, updates the repo, and builds a static `x86_64-unknown-linux-musl` artifact with:

   ```bash
   cargo build --release --locked --bin lnurl-server --target ${TARGET}
   ```

3. The release artifact is packaged as `lnurl-server-${TARGET}-${VERSION}.tar.gz` by `ci/tasks/build-release.sh` and uploaded through the `gh-release` resource.
4. The `release-docker` job runs after `release`, writes `VERSION`, `COMMITHASH`, and `BUILDTIME` to `repo/.env`, then builds `Dockerfile` with Kaniko:

   ```bash
   /kaniko/executor \
     --dockerfile=repo/Dockerfile \
     --context=repo \
     --use-new-run \
     --single-snapshot \
     --cache=false \
     --no-push \
     --tar-path=image/image.tar
   ```

5. The image tar is published by the `latest-image` resource with the version from `version/version` as an additional tag.
6. The `bump-image-in-chart` job runs `pipeline-tasks/ci/tasks/bump-image-digest.sh` against the external `charts-repo` resource with `CHARTS_SUBDIR=blink-lnurl-server`, then opens a GitHub PR from `bot-bump-blink-lnurl-server-image` to `main`.

Local release verification is available with:

```bash
nix develop -c make release-check
```

`make release-check` runs formatting, Clippy, Rust tests, PostgreSQL integration tests, Bats E2E tests, and `cargo audit`.

## Environment setup

Configure the runtime with `LNURL_` environment variables or the equivalent `lnurl.conf` TOML keys. See [CONFIGURATION.md](CONFIGURATION.md) for the complete list.

Minimum production-oriented settings usually include:

| Variable | Purpose |
|----------|---------|
| `DEPLOYMENT_ENV` | Provider selector. Use `production`, `staging`, or `local`; when unset or blank, runtime defaults to `production`. Runtime derives Spark/LNURL and Blink settings from this one value. |
| `LNURL_ADDRESS` | Bind address for the HTTP server, for example `0.0.0.0:8080`. |
| `LNURL_DB_URL` | PostgreSQL or SQLite connection string; PostgreSQL URLs start with `postgres`. |
| `LNURL_DOMAINS` | Comma-separated Lightning Address / LNURL domains accepted by the server. |
| `LNURL_SCHEME` | URL scheme used in generated callback and webhook URLs, normally `https` in production. |
| `LNURL_WEBHOOK_DOMAIN` | Domain used to build provider callback URLs for `/webhook` and `/webhook/blink`; startup fails without this value. |
| `LNURL_SSP_AUTH_SEED` | Stable hex-encoded 32-byte Spark SSP authentication seed. |
| `LNURL_SPARK_NETWORK` | Optional Spark/LNURL network override when a deployment must differ from the `DEPLOYMENT_ENV` default. |
| `LNURL_BLINK_GRAPHQL_ENDPOINT` | Optional Blink GraphQL override when a deployment must differ from the `DEPLOYMENT_ENV` default. |
| `LNURL_INTERNAL_JWKS_URL` or `LNURL_INTERNAL_JWKS_PATH` | JWKS source for internal Blink Core JWT authentication, when `/internal/...` routes are used. |
| `LNURL_INTERNAL_JWT_ISSUER` and `LNURL_INTERNAL_JWT_AUDIENCE` | Expected issuer and audience for internal RS256 JWTs. |

For managed deployments, set secrets in the deployment platform rather than committing them to the repository.

Provider mapping is fixed as:

- `production` → Spark/LNURL `mainnet`, Blink production GraphQL.
- `staging` → Spark/LNURL `regtest`, Blink signet behavior with `https://api.staging.blink.sv/graphql`.
- `local` → Spark/LNURL `regtest`, Blink local behavior through the explicitly configured `LNURL_BLINK_GRAPHQL_ENDPOINT`.

Spark staging stays explicitly mapped to `regtest` for now so the later Spark `regtest -> signet` switch is localized to one startup match arm.

If a deployment needs to diverge from those defaults, set `LNURL_SPARK_NETWORK` and/or `LNURL_BLINK_GRAPHQL_ENDPOINT` explicitly.

Database migrations are embedded for both PostgreSQL and SQLite. Set `LNURL_AUTO_MIGRATE=true` only when the instance should apply migrations during startup; otherwise run migrations through the release/deployment process before starting new instances.

## Rollback procedure

No automated rollback job or rollback script is defined in this repository.

Recommended rollback approach for the detected release flow:

1. Identify the previous healthy GitHub release artifact or container image digest from the release/charts history.
2. Revert or update the chart image digest in the deployment configuration to the previous known-good digest.
3. Redeploy the chart through the platform that consumes `blinkbitcoin/charts`.
4. Confirm readiness with:

   ```bash
   curl -fsS https://<deployment-host>/health
   ```

5. Check application logs for startup, database, webhook, and provider errors after rollback.

## Monitoring

No Sentry, Datadog, New Relic, or OpenTelemetry dependency or config file is present in this repository. Runtime observability is based on:

- Structured logs written to stdout through `tracing_subscriber` in `src/main.rs`.
- Log filtering with `LNURL_LOG_LEVEL` / `--log-level`.
- Health checks through `GET /health`, registered in `src/main.rs`.
- Concourse Slack notification wiring in `ci/pipeline.yml` and `ci/values.yml`; notifications are disabled by `disable_notifications: true` in the checked-in values.
