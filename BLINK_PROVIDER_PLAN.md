# Blink Custodial Wallet Provider Plan

## Goals

- Keep the existing Breez/Spark SDK-compatible API endpoints and response shapes.
- Add Blink custodial wallet support as a second provider.
- Support multiple identifiers per Blink account, initially usernames and phone numbers.
- Support virtual wallet modifiers for Blink identifiers: default, `+btc`, and `+usd`.
- Use Blink public GraphQL operations for invoice creation and payment status.
- Preserve LUD-21 verify and NIP-57 zap support across providers.
- Introduce a provider/adapter architecture so Spark and Blink behavior is cleanly separated.
- Add authenticated internal APIs for Blink Core registration, lookup, settlement notification, and transfer to Spark.
- Update unit, integration, and Bats/e2e coverage using a mocked Blink GraphQL endpoint, not Blink quickstart.

## Non-Goals

- Do not transfer balances or wallet funds between providers.
- Do not require Blink API authentication for GraphQL calls; only public queries/mutations are used.
- Do not break the existing Spark mobile SDK endpoints.
- Do not store `identifier+btc` or `identifier+usd` as separate identifiers; they are virtual aliases.

## Current State

- The current data model is Spark-specific and centered on `users(domain, pubkey, name, description)`.
- LNURL discovery resolves a single username via `get_user_by_name`.
- Invoice creation directly calls `SparkWallet::create_lightning_invoice` from the route handler.
- Invoices are keyed by payment hash and linked to `user_pubkey`.
- LUD-21 verify reads local invoice state only.
- Zaps and sender comments are keyed to payment hash and `user_pubkey`.
- Internal auth currently verifies client certificates but does not expose caller identity or scopes.

## Key Decisions

- Spark remains the default provider for existing public registration endpoints.
- Existing Spark endpoints must remain compatible with Breez SDK request/response fields and auth behavior.
- Username validation for both Spark and Blink must match Blink Core `checkedToUsername` rules.
- Phone identifiers are Blink-only initially and normalize like Blink Core `checkedToPhoneNumber`.
- Blink accounts must provide a required `defaultWallet`.
- Blink wallet modifiers are virtual:
  - `identifier` uses the account default wallet.
  - `identifier+btc` forces the BTC wallet.
  - `identifier+usd` forces the USD wallet.
- Phone modifiers are supported too:
  - `573005871212+usd`
  - `+573005871212+usd`
  - `00573005871212+usd`
- Blink account re-registration must return an error.
- Identifier conflicts across providers return `409 Conflict`.
- Blink settlement is push-first via authenticated webhook, with `lnInvoicePaymentStatusByHash` fallback if the preimage is absent.
- Cross-provider transfer only moves identifier ownership.
- Blink-to-Spark transfer is authorized by Blink internal auth, not by a Spark source signature.

## Identifier Rules

### Username Identifiers

All Spark and Blink username identifiers must use Blink Core `checkedToUsername` rules:

```regex
^(?![13_]|bc1|lnbc1)(?=.*[a-z])[0-9a-z_]{3,50}$
```

Rules:

- 3 to 50 characters.
- ASCII letters, digits, and underscore only.
- Must contain at least one letter.
- Cannot start with `1`.
- Cannot start with `3`.
- Cannot start with `_`.
- Cannot start with `bc1`.
- Cannot start with `lnbc1`.
- Store and query lowercase.

Because there are no existing registrations, no grandfathering of legacy username formats is needed.

### Phone Identifiers

Phone identifiers are Blink-only initially.

Normalize like Blink Core `checkedToPhoneNumber`:

```ts
const trimmedValue = value.trim()
const normalizedPhone = trimmedValue.replace(/^(\+|00)?(.*)/g, "+$2")
```

Then validate with a phone-number library, preferably `rlibphonenumber` or an equivalent Rust crate.

Examples that should normalize to the same stored identifier if valid:

- `573005871212` -> `+573005871212`
- `+573005871212` -> `+573005871212`
- `00573005871212` -> `+573005871212`

Numeric-only values are never valid usernames because usernames must include at least one letter. This avoids username/phone conflicts.

### Wallet Modifier Parsing

For public LNURL lookup and callback paths:

- Parse a trailing `+btc` or `+usd` modifier first.
- The modifier is case-insensitive.
- The base identifier is then normalized as phone or username.
- The modifier selects the wallet for Blink invoice creation.
- Spark ignores wallet modifiers or rejects them as unsupported. Recommended behavior: reject Spark modifier usage with LNURL `ERROR` to avoid confusing senders.

Examples:

- `/lnurlp/alice` -> username `alice`, default wallet.
- `/lnurlp/alice+btc` -> username `alice`, BTC wallet.
- `/lnurlp/alice+usd` -> username `alice`, USD wallet.
- `/lnurlp/573005871212` -> phone `+573005871212`, default wallet.
- `/lnurlp/%2B573005871212` -> phone `+573005871212`, default wallet.
- `/lnurlp/00573005871212+usd` -> phone `+573005871212`, USD wallet.

## Data Model

Replace the user-centric model with provider-neutral account and identifier tables.

### `accounts`

Columns:

- `id`: internal account id.
- `provider`: `spark` or `blink`.
- `description`.
- `created_at`.
- `updated_at`.

### `account_identifiers`

Columns:

- `id`.
- `account_id`.
- `domain`.
- `identifier`.
- `identifier_type`: `username` or `phone` initially.
- `is_primary`.
- `created_at`.
- `updated_at`.

Constraints:

- Unique `(domain, identifier)` across all providers.
- Foreign key to `accounts(id)`.

Notes:

- Store normalized canonical identifiers only.
- Do not store `identifier+btc` or `identifier+usd`.

### `spark_accounts`

Columns:

- `account_id`.
- `pubkey`.

Constraints:

- Unique `pubkey`.
- Foreign key to `accounts(id)`.

### `blink_accounts`

Columns:

- `account_id`.
- `blink_account_id`.
- `btc_wallet_id`.
- `usd_wallet_id`.
- `default_wallet`: `btc` or `usd`.

Constraints:

- Unique `blink_account_id`.
- Foreign key to `accounts(id)`.

### `invoices`

Add or migrate to:

- `payment_hash` primary key.
- `account_id`.
- `provider`: `spark` or `blink`.
- `invoice`.
- `preimage`.
- `invoice_expiry`.
- `created_at`.
- `updated_at`.
- `domain`.
- `amount_received_sat`.
- `wallet_kind`: `btc`, `usd`, nullable for Spark.
- `provider_metadata`: optional JSON/text for provider-specific data.

The current `user_pubkey` column can remain temporarily during migration work but route logic should move to `account_id`.

### Zap And Metadata Tables

Update records that currently store `user_pubkey` to use `account_id` or support a migration bridge until the old model is fully removed.

Affected areas:

- `zaps`.
- `sender_comments`.
- metadata listing queries.
- webhook payload joins.

## Migrations

Add equivalent SQLite and Postgres migrations.

Recommended phased migration:

1. Create new account/provider tables.
2. Add nullable `account_id`, `provider`, and `wallet_kind` columns to invoice-related tables.
3. Backfill current Spark `users` rows into:
   - `accounts(provider = 'spark')`.
   - `spark_accounts(pubkey)`.
   - `account_identifiers(domain, identifier, type = 'username')`.
4. Backfill invoices and zap/comment rows where possible.
5. Update code to read/write new tables.
6. Remove old `users` dependency in a later cleanup migration.

Because there are no existing registrations, the backfill path can still be implemented for safety but should be simple.

## Provider Architecture

Introduce a provider trait around invoice creation and payment status.

```rust
#[async_trait]
pub trait LnurlProvider {
    fn kind(&self) -> ProviderKind;

    async fn create_invoice(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, ProviderError>;

    async fn payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentStatus, ProviderError>;
}
```

Suggested shared models:

- `ProviderKind`: `Spark`, `Blink`.
- `WalletKind`: `Btc`, `Usd`.
- `CreateInvoiceRequest`:
  - account/recipient details.
  - amount in millisats or sats.
  - description hash.
  - expiry.
  - wallet kind.
  - include Spark address flag for Spark.
- `CreateInvoiceResponse`:
  - Bolt11 invoice.
  - payment hash.
  - expiry timestamp.
- `PaymentStatus`:
  - settled bool.
  - preimage optional.
  - amount received optional.

Implementations:

- `SparkProvider`: wraps current Spark wallet behavior and local status.
- `BlinkProvider`: wraps Blink GraphQL client.

The route layer should resolve the recipient, parse modifiers, validate LNURL params, and dispatch to the provider. It should not call provider-specific SDKs directly.

## Blink Client Crate

Convert the repo to a workspace and add an independent crate:

```text
crates/blink-client
```

Responsibilities:

- Own Blink GraphQL schema and query documents.
- Provide typed Rust methods for public operations.
- Support configurable endpoint URL.
- Have no authentication support initially.
- Expose errors that distinguish transport, GraphQL, malformed response, and semantic API failures.

Required operations:

- `LnInvoiceCreateOnBehalfOfRecipient` for BTC invoices.
- `lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient` for USD invoices denominated in BTC.
- `lnInvoicePaymentStatusByHash` for status and preimage.

Endpoints:

- Production: `https://api.blink.sv/graphql`.
- Staging: `https://api.staging.blink.sv/graphql`.
- Tests: local mock URL.

Schema management:

- Check in the GraphQL schema used for codegen.
- Add a script or task to sync schema from prod/staging.
- CI should eventually detect stale generated code/schema drift.

## Registration APIs

### Existing Spark Registration

Preserve current endpoints and response shape:

- `GET /lnurlpay/available/{identifier}`.
- `POST /lnurlpay/{pubkey}`.
- `DELETE /lnurlpay/{pubkey}`.
- `POST /lnurlpay/{pubkey}/recover`.
- `GET /lnurlpay/{pubkey}/metadata`.
- invoice paid endpoints.

Changes:

- Spark registration writes to the new account tables.
- Spark username validation uses Blink Core username rules.
- Keep current request fields, response fields, signature behavior, and HTTP status style.

### Blink Registration

Add authenticated internal endpoint:

```http
POST /internal/blink/accounts
```

Payload:

```json
{
  "domain": "example.com",
  "accountId": "blink-account-id",
  "btcWalletId": "btc-wallet-id",
  "usdWalletId": "usd-wallet-id",
  "defaultWallet": "btc",
  "description": "Alice wallet",
  "identifiers": [
    { "type": "username", "value": "alice" },
    { "type": "phone", "value": "573005871212" }
  ]
}
```

Behavior:

- `domain` is required.
- `defaultWallet` is required.
- Normalize and validate identifiers before persistence.
- If `blinkAccountId` already exists, return `409 Conflict`.
- If any identifier is already owned by another account/provider, return `409 Conflict` with `identifier already taken`.
- Create exactly one Blink account and all identifiers atomically.

## Auth Design

Use the existing certificate-auth foundation but improve it for internal APIs.

Do not model Blink Core as a fake Spark account or static Spark pubkey. Service auth and wallet ownership should remain separate.

Enhancements:

- Extract authenticated principal from validated certificate.
- Include cert fingerprint and subject/common name.
- Add scoped authorization for internal routes.
- Scopes can initially be configured statically and moved to DB later.

Suggested scopes:

- `blink:accounts:create`.
- `blink:accounts:read`.
- `blink:settlements:write`.
- `blink:transfers:write`.

Internal routes should require these scopes. Existing public Spark API should keep its current Spark signature validation.

## Internal Lookup API

Add provider-neutral authenticated lookup:

```http
GET /internal/domains/{domain}/identifiers/{identifier}
```

Behavior:

- Parse wallet modifier if present.
- Normalize identifier.
- Resolve base identifier.
- Return account/provider details.

Response example:

```json
{
  "accountId": "internal-account-id",
  "provider": "blink",
  "domain": "example.com",
  "identifier": "+573005871212",
  "identifierType": "phone",
  "selectedWallet": "usd",
  "identifiers": [
    { "type": "username", "value": "alice" },
    { "type": "phone", "value": "+573005871212" }
  ],
  "blink": {
    "accountId": "blink-account-id",
    "btcWalletId": "btc-wallet-id",
    "usdWalletId": "usd-wallet-id",
    "defaultWallet": "btc"
  }
}
```

## LNURL Discovery

Public routes stay:

- `/.well-known/lnurlp/{identifier}`.
- `/lnurlp/{identifier}`.

Flow:

1. Reject empty identifier.
2. Parse optional wallet modifier.
3. Normalize identifier.
4. Resolve account by `(domain, identifier)`.
5. Return LUD-06 pay response.

The callback should preserve the identifier string used by the payer where practical:

```text
/lnurlp/{identifier}/invoice
```

For Blink, metadata should be based on the resolved account and the identifier that was requested. For Spark, preserve existing behavior.

## Invoice Creation

Public route stays:

```http
GET /lnurlp/{identifier}/invoice
```

Flow:

1. Resolve account and wallet modifier.
2. Validate amount.
3. Validate comments.
4. Validate Nostr zap request if provided.
5. Build description hash exactly as LNURL/NIP-57 expects.
6. Dispatch to provider.
7. Parse returned Bolt11.
8. Store local invoice record with provider/account/wallet metadata.
9. Store zap request and sender comment if present.
10. Return existing LNURL callback response shape:

```json
{
  "pr": "bolt11",
  "routes": [],
  "verify": "https://example.com/verify/payment_hash"
}
```

### Spark Invoice Creation

Use the current `SparkWallet::create_lightning_invoice` behavior through `SparkProvider`.

### Blink Invoice Creation

Use `BlinkProvider` and `blink-client`:

- BTC wallet: call `LnInvoiceCreateOnBehalfOfRecipient`.
- USD wallet: call `lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient`.

Store:

- provider `blink`.
- internal account id.
- wallet kind.
- payment hash.
- invoice.
- expiry.
- domain.

## LUD-21 Verify

Public route stays:

```http
GET /verify/{payment_hash}
```

Flow:

1. Load invoice by payment hash.
2. If not found, return LUD-21-style error.
3. Dispatch by invoice provider.
4. Spark:
   - Use local preimage state as today.
5. Blink:
   - If local preimage exists, return settled.
   - Otherwise call `lnInvoicePaymentStatusByHash`.
   - If Blink returns settled with preimage, call central paid-invoice handler to persist preimage, enqueue zaps, and enqueue webhooks.
6. Return:

```json
{
  "status": "OK",
  "settled": true,
  "preimage": "...",
  "pr": "bolt11"
}
```

## Settlement Notification

### Spark

Keep existing Spark webhook and invoice-paid endpoint behavior.

### Blink

Add authenticated internal endpoint:

```http
POST /webhook/blink
```

Payload with preimage:

```json
{
  "paymentHash": "...",
  "preimage": "...",
  "amountSat": 123
}
```

Payload without preimage:

```json
{
  "paymentHash": "...",
  "amountSat": 123
}
```

Behavior:

- Require internal auth scope `blink:settlements:write`.
- Load local invoice and ensure provider is Blink.
- If preimage is present, verify it matches payment hash and persist it.
- If preimage is absent, call `lnInvoicePaymentStatusByHash` and persist returned preimage if settled.
- Use the same central `handle_invoice_paid` path to trigger zaps and webhooks.

## Zaps

Keep current NIP-57 validation and receipt publishing behavior, but make invoice ownership provider-neutral.

Flow:

1. LNURL callback receives `nostr` zap request.
2. Validate zap request.
3. Create provider invoice.
4. Store zap by payment hash and account id.
5. When invoice is paid and preimage is stored, enqueue zap receipt.
6. Background processor publishes zap receipt.

For Blink, settlement can arrive through:

- Blink internal webhook with preimage.
- Blink internal webhook without preimage plus status fallback.
- LUD-21 verify polling plus status query fallback.

## Transfers

Transfers move identifier ownership only.

### Existing Spark Transfer

Preserve existing endpoint compatibility:

```http
POST /lnurlpay/{pubkey}/transfer
```

Adapt implementation to move identifiers in `account_identifiers` while preserving current signature semantics and response shape.

### Blink To Spark Transfer

Add authenticated internal endpoint:

```http
POST /internal/identifiers/transfer-to-spark
```

Payload:

```json
{
  "domain": "example.com",
  "identifier": "alice",
  "targetSparkPubkey": "...",
  "description": "Alice Spark wallet"
}
```

Behavior:

- Require internal auth scope `blink:transfers:write`.
- Normalize identifier.
- Verify current owner is Blink.
- Create Spark account automatically if target pubkey has never registered.
- Atomically move the identifier to the Spark account.
- Historical invoices remain attached to the original Blink account.
- New invoices use Spark.

## Webhooks To External Domains

Current external webhook delivery should become provider-neutral.

Payload naming should either:

- Keep the current `spark_payment_received` template for backward compatibility only when provider is Spark.
- Add a new provider-neutral template such as `lnurl_payment_received` for Blink and future providers.

Recommended new payload:

```json
{
  "template": "lnurl_payment_received",
  "data": {
    "provider": "blink",
    "payment_hash": "...",
    "invoice": "...",
    "preimage": "...",
    "amount_sat": 123,
    "lightning_address": "alice@example.com",
    "sender_comment": "...",
    "timestamp": 123456789
  }
}
```

## Configuration

Add config fields:

- `LNURL_BLINK_GRAPHQL_ENDPOINT`.
- `LNURL_BLINK_ENVIRONMENT`: optional helper for `prod`/`staging` defaults.
- `LNURL_INTERNAL_AUTH_CA_CERT` or reuse current CA config if route scope separation is implemented cleanly.
- `LNURL_INTERNAL_AUTH_ALLOWED_CLIENTS` or equivalent scoped client config.

Existing Spark config remains supported.

## Tests

### Unit Tests

Add tests for:

- Blink username validation.
- Spark username validation using Blink rules.
- Phone normalization:
  - `573005871212`.
  - `+573005871212`.
  - `00573005871212`.
- Wallet modifier parsing:
  - usernames.
  - phones.
  - invalid modifiers.
- Identifier conflict detection.
- Provider dispatch.
- Blink settlement fallback when webhook lacks preimage.
- LUD-21 verify updating local invoice state from Blink status.
- Transfer from Blink to Spark.

### Repository Integration Tests

Run against SQLite and Postgres where current test strategy supports it.

Add tests for:

- Creating Spark account through compatibility path.
- Creating Blink account with username and phone identifiers.
- Unique `(domain, identifier)` across providers.
- Lookup by username.
- Lookup by normalized phone.
- Invoice insertion with provider/account/wallet fields.
- Metadata queries by account id.
- Webhook payload joins.
- Atomic transfer of identifier ownership.

### Blink Client Tests

Use Wiremock, Mockito, or equivalent lightweight HTTP mocking.

Test:

- BTC invoice mutation request shape.
- USD invoice mutation request shape.
- Status query request shape.
- GraphQL errors.
- Missing fields/malformed responses.
- Endpoint configuration.

### Bats/E2E Tests

Keep existing Bats tests for Spark compatibility.

Add a mocked Blink GraphQL service. Do not install Blink quickstart.

Add E2E tests:

- Register Blink account with username and phone.
- Reject Blink re-registration for same Blink account id.
- Reject identifier conflict.
- Discover Blink username.
- Discover Blink phone using `573005871212`.
- Discover Blink phone using `%2B573005871212`.
- Create Blink BTC invoice via `identifier+btc`.
- Create Blink USD invoice via `identifier+usd`.
- Create Blink invoice via default wallet.
- Verify unsettled Blink invoice.
- Verify settled Blink invoice with preimage from status query.
- Blink webhook with preimage marks invoice paid.
- Blink webhook without preimage falls back to status query.
- Zap request stores zap and publishes receipt after Blink settlement.
- Transfer Blink identifier to Spark and then create Spark invoice through same identifier.

## Implementation Order

1. Add identifier validation and normalization module.
2. Add account/provider migrations for SQLite and Postgres.
3. Extend repository traits and implementations for account and identifier operations.
4. Update existing Spark endpoints to write/read the new account model while preserving API compatibility.
5. Add provider trait and move current Spark invoice creation behind `SparkProvider`.
6. Convert to workspace and add `crates/blink-client`.
7. Add Blink GraphQL schema/query documents and mocked client tests.
8. Add `BlinkProvider`.
9. Add internal auth principal/scopes.
10. Add Blink registration endpoint.
11. Add provider-neutral internal lookup endpoint.
12. Update LNURL discovery and invoice callback to resolve provider accounts and wallet modifiers.
13. Update LUD-21 verify to dispatch provider status checks.
14. Add Blink settlement webhook with status fallback.
15. Update zaps, sender comments, metadata, and webhook payload paths to use account ids.
16. Add Blink-to-Spark identifier transfer endpoint.
17. Add Bats/e2e mock Blink GraphQL service and tests.
18. Remove obsolete user-centric code once all tests pass.

## Risks And Mitigations

- Risk: tightening Spark username validation could surprise clients.
  - Mitigation: endpoint shape remains compatible; only invalid names are rejected before launch.
- Risk: phone normalization could collide with numeric usernames.
  - Mitigation: usernames require at least one letter, so numeric-only values route to phone normalization.
- Risk: `+` in URL path handling can vary by clients.
  - Mitigation: support both encoded `+` and unencoded `+` in path tests; document `%2B` as safest.
- Risk: Blink webhook may omit preimage.
  - Mitigation: always support `lnInvoicePaymentStatusByHash` fallback.
- Risk: provider-specific invoice behavior leaks into routes.
  - Mitigation: route layer only resolves recipients and calls provider trait.
- Risk: migration touches many query paths.
  - Mitigation: phase migration, keep old columns temporarily, and add shared repository tests.

## Clean-Context Implementation Appendix

This appendix is written for an implementation agent starting with no conversation context. Treat the sections above as product requirements and this appendix as execution guidance for this repository.

### Repository Map

Current important files:

- `Cargo.toml`: single-package Cargo manifest today. Convert to workspace when adding `crates/blink-client`.
- `src/main.rs`: config, server state construction, route registration, Spark wallet setup, webhook registration.
- `src/state.rs`: application state. Currently stores Spark-specific objects directly.
- `src/routes/mod.rs`: current route module root; handlers live in submodules for account, internal, LNURL pay, webhooks, and zaps.
- `src/repository.rs`: current database trait and data structs. It is user/pubkey-centric.
- `src/sqlite/repository.rs`: SQLite repository implementation.
- `src/postgresql/repository.rs`: Postgres repository implementation.
- `src/models.rs`: current API request/response structs.
- `src/user.rs`: current username regex and `User` model. This should be replaced or reduced to compatibility types.
- `src/invoice_paid.rs`: central paid-invoice logic. Reuse this for Spark webhook, Blink webhook, and Blink verify fallback.
- `src/zap.rs`: zap persistence/background processing.
- `src/webhook_notify.rs`: builds outbound webhook payloads from paid invoices.
- `src/webhooks/*`: outbound webhook delivery storage and worker.
- `src/auth.rs`: current certificate auth middleware.
- `migrations/sqlite/*`: SQLite migrations.
- `migrations/postgres/*`: Postgres migrations.
- `bats/*`: current e2e tests.
- `bats/helpers/common.bash`: helper functions for current e2e stack and Spark registration calls.
- `scripts/start-local-stack.sh`: local e2e startup.

Current behavior to preserve:

- `POST /lnurlpay/{pubkey}` accepts current Spark registration JSON and returns `lnurl` and `lightning_address`.
- `DELETE /lnurlpay/{pubkey}` accepts current Spark unregister JSON and returns empty success.
- `POST /lnurlpay/{pubkey}/recover` accepts current Spark recover JSON and returns current fields.
- `GET /lnurlpay/available/{identifier}` returns `{ "available": true|false }`.
- `GET /.well-known/lnurlp/{identifier}` and `GET /lnurlp/{identifier}` return a LUD-06 pay response.
- `GET /lnurlp/{identifier}/invoice` returns `{ "pr", "routes", "verify" }` or LNURL `ERROR` JSON.
- `GET /verify/{payment_hash}` returns LUD-21 verify JSON.
- Existing signature validation for Spark endpoints must remain compatible.

### Suggested New Modules

Add these modules in the main `lnurl-server` crate:

- `src/identifier.rs`: username validation, phone normalization, modifier parsing.
- `src/routes/account.rs`: provider-neutral account route handlers and compatibility flows.
- `src/providers.rs`: provider trait and shared provider models.
- `src/providers.rs`: Spark provider implementation.
- `src/providers.rs`: Blink provider implementation using `blink-client`.
- `src/routes/internal.rs`: authenticated internal APIs. If restructuring routes is too broad, add internal handlers to `src/routes/mod.rs` first and split later.

Add this independent crate:

- `crates/blink-client/Cargo.toml`.
- `crates/blink-client/src/lib.rs`.
- `crates/blink-client/src/client.rs`.
- `crates/blink-client/src/error.rs`.
- `crates/blink-client/graphql/schema.graphql`.
- `crates/blink-client/graphql/*.graphql` for operation documents.

### Cargo Workspace Layout

Current root `Cargo.toml` is both package and workspace with an empty `[workspace]`. A safe conversion is:

```toml
[workspace]
members = [".", "crates/blink-client"]

[package]
name = "lnurl"
edition = "2024"
version = "0.1.1-dev"
```

Keep the root package as the server so existing binary names and CI keep working.

Root dependency additions likely needed:

```toml
blink-client = { path = "crates/blink-client" }
rlibphonenumber = "..."
uuid = { version = "...", features = ["v4", "serde"] }
```

Only add `uuid` if choosing UUID internal account ids. A text id generated by the database is also acceptable, but explicit UUIDs are easier for SQLite/Postgres parity.

Blink client crate dependencies likely needed:

```toml
anyhow = "1"
graphql_client = "0.16"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
```

### Identifier Module Details

Implement `src/identifier.rs` with explicit types so route logic cannot accidentally mix raw and normalized identifiers.

Suggested types:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierType {
    Username,
    Phone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletModifier {
    Btc,
    Usd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIdentifier {
    pub raw_base: String,
    pub normalized: String,
    pub identifier_type: IdentifierType,
    pub wallet_modifier: Option<WalletModifier>,
}
```

Functions:

```rust
pub fn normalize_username(input: &str) -> Result<String, IdentifierError>;
pub fn normalize_phone(input: &str) -> Result<String, IdentifierError>;
pub fn parse_wallet_modifier(input: &str) -> (String, Option<WalletModifier>);
pub fn parse_public_identifier(input: &str) -> Result<ParsedIdentifier, IdentifierError>;
pub fn parse_typed_identifier(kind: IdentifierType, input: &str) -> Result<String, IdentifierError>;
```

Username implementation details:

- Trim input before validation.
- Lowercase before storage/query.
- Match exactly the Blink regex semantically: `^(?![13_]|bc1|lnbc1)(?=.*[a-z])[0-9a-z_]{3,50}$`, case-insensitive before lowercasing.
- Return the same user-facing route error string currently used for invalid usernames unless adding internal endpoint errors.

Phone implementation details:

- Trim input.
- Convert optional `+` or `00` prefix to a single leading `+`, following Blink Core.
- Validate possible and valid with phone library.
- Store `phone_number.number()` in canonical E.164 with `+`.
- Public lookup should attempt phone parsing first when the input is numeric, starts with `+`, or starts with `00`. If phone parse succeeds, use phone. Otherwise attempt username.
- Since usernames require a letter, numeric values cannot collide with usernames.

Modifier parsing details:

- Only strip a final, case-insensitive `+btc` or `+usd` suffix.
- Strip modifier before phone normalization.
- `alice+btc` -> base `alice`, modifier `Btc`.
- `+573005871212+usd` -> base `+573005871212`, modifier `Usd`.
- `573005871212+usd` -> base `573005871212`, modifier `Usd`.
- `alice+foo` has no recognized modifier; then username validation fails because `+` is not allowed.

### Account Model Details

Implement `src/account.rs` or equivalent.

Suggested Rust structs:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Spark,
    Blink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletKind {
    Btc,
    Usd,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub id: String,
    pub provider: ProviderKind,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct AccountIdentifier {
    pub id: String,
    pub account_id: String,
    pub domain: String,
    pub identifier: String,
    pub identifier_type: IdentifierType,
    pub is_primary: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct SparkAccount {
    pub account_id: String,
    pub pubkey: String,
}

#[derive(Debug, Clone)]
pub struct BlinkAccount {
    pub account_id: String,
    pub blink_account_id: String,
    pub btc_wallet_id: String,
    pub usd_wallet_id: String,
    pub default_wallet: WalletKind,
}

#[derive(Debug, Clone)]
pub struct Recipient {
    pub account: Account,
    pub identifier: AccountIdentifier,
    pub all_identifiers: Vec<AccountIdentifier>,
    pub spark: Option<SparkAccount>,
    pub blink: Option<BlinkAccount>,
}
```

Store enums as lowercase text in both SQLite and Postgres for portability.

### Migration DDL Sketch

Create matching migrations under both `migrations/sqlite/` and `migrations/postgres/` with a timestamp after the current latest migration.

SQLite sketch:

```sql
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('spark', 'blink')),
    description TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE account_identifiers (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    identifier TEXT NOT NULL,
    identifier_type TEXT NOT NULL CHECK (identifier_type IN ('username', 'phone')),
    is_primary INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(domain, identifier)
);

CREATE INDEX idx_account_identifiers_account_id ON account_identifiers(account_id);
CREATE INDEX idx_account_identifiers_lookup ON account_identifiers(domain, identifier);

CREATE TABLE spark_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    pubkey TEXT NOT NULL UNIQUE
);

CREATE TABLE blink_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    blink_account_id TEXT NOT NULL UNIQUE,
    btc_wallet_id TEXT NOT NULL,
    usd_wallet_id TEXT NOT NULL,
    default_wallet TEXT NOT NULL CHECK (default_wallet IN ('btc', 'usd'))
);

ALTER TABLE invoices ADD COLUMN account_id TEXT;
ALTER TABLE invoices ADD COLUMN provider TEXT;
ALTER TABLE invoices ADD COLUMN wallet_kind TEXT;
ALTER TABLE invoices ADD COLUMN provider_metadata TEXT;

ALTER TABLE zaps ADD COLUMN account_id TEXT;
ALTER TABLE sender_comments ADD COLUMN account_id TEXT;
```

Postgres sketch:

```sql
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('spark', 'blink')),
    description TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE account_identifiers (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    identifier TEXT NOT NULL,
    identifier_type TEXT NOT NULL CHECK (identifier_type IN ('username', 'phone')),
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(domain, identifier)
);

CREATE INDEX idx_account_identifiers_account_id ON account_identifiers(account_id);
CREATE INDEX idx_account_identifiers_lookup ON account_identifiers(domain, identifier);

CREATE TABLE spark_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    pubkey TEXT NOT NULL UNIQUE
);

CREATE TABLE blink_accounts (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    blink_account_id TEXT NOT NULL UNIQUE,
    btc_wallet_id TEXT NOT NULL,
    usd_wallet_id TEXT NOT NULL,
    default_wallet TEXT NOT NULL CHECK (default_wallet IN ('btc', 'usd'))
);

ALTER TABLE invoices ADD COLUMN account_id TEXT;
ALTER TABLE invoices ADD COLUMN provider TEXT;
ALTER TABLE invoices ADD COLUMN wallet_kind TEXT;
ALTER TABLE invoices ADD COLUMN provider_metadata TEXT;

ALTER TABLE zaps ADD COLUMN account_id TEXT;
ALTER TABLE sender_comments ADD COLUMN account_id TEXT;
```

Backfill notes:

- If there are rows in `users`, create Spark accounts for them.
- Existing `users.name` may not satisfy new username rules. Product says there are no existing registrations, so this is not expected. If encountered, fail migration only if unavoidable; otherwise preserve exact old identifier for backfill and let code reject new invalid identifiers.
- For each `users` row, generated `account_id` can be deterministic such as `spark:{domain}:{pubkey}` or a UUID. UUID is cleaner but deterministic ids simplify SQL-only backfill.
- Backfill `invoices.account_id` by joining `invoices.user_pubkey` to `spark_accounts.pubkey` when possible and set `provider = 'spark'`.
- Backfill `zaps.account_id` and `sender_comments.account_id` similarly when possible.
- Do not make `account_id` columns `NOT NULL` until all write paths are migrated and tests pass.

### Repository Trait Additions

Extend `src/repository.rs` with account operations. Keep existing methods until call sites are migrated.

Suggested errors:

```rust
pub enum LnurlRepositoryError {
    NameTaken,
    IdentifierTaken,
    AccountExists,
    AccountNotFound,
    SourceNotOwner,
    General(anyhow::Error),
}
```

Suggested trait methods:

```rust
async fn get_recipient_by_identifier(
    &self,
    domain: &str,
    identifier: &str,
) -> Result<Option<Recipient>, LnurlRepositoryError>;

async fn get_recipient_by_account_id(
    &self,
    account_id: &str,
) -> Result<Option<Recipient>, LnurlRepositoryError>;

async fn get_spark_account_by_pubkey(
    &self,
    pubkey: &str,
) -> Result<Option<Recipient>, LnurlRepositoryError>;

async fn create_or_update_spark_registration(
    &self,
    domain: &str,
    pubkey: &str,
    username: &str,
    description: &str,
) -> Result<Recipient, LnurlRepositoryError>;

async fn delete_spark_registration(
    &self,
    domain: &str,
    pubkey: &str,
) -> Result<(), LnurlRepositoryError>;

async fn create_blink_account(
    &self,
    request: &NewBlinkAccount,
) -> Result<Recipient, LnurlRepositoryError>;

async fn transfer_identifier_to_spark(
    &self,
    domain: &str,
    identifier: &str,
    target_pubkey: &str,
    description: &str,
) -> Result<Recipient, LnurlRepositoryError>;
```

Important repository semantics:

- `create_blink_account` must be transactional.
- If Blink account id already exists, return `AccountExists`.
- If any identifier conflicts, return `IdentifierTaken`.
- `create_or_update_spark_registration` must preserve current behavior: one Spark pubkey can update its username/description. Because there are no existing registrations, exact old `REPLACE INTO users` semantics are less important, but Breez response compatibility is required.
- `delete_spark_registration` should remove the Spark account's identifier for the current domain/pubkey. If an account has no identifiers left, deleting the account is acceptable.
- `transfer_identifier_to_spark` must create the Spark account if missing and atomically move only the requested identifier.

### Invoice Struct Changes

Update `Invoice` in `src/repository.rs` to include account/provider fields while keeping old `user_pubkey` temporarily if needed.

Suggested transitional struct:

```rust
pub struct Invoice {
    pub payment_hash: String,
    pub account_id: Option<String>,
    pub provider: Option<ProviderKind>,
    pub user_pubkey: String,
    pub invoice: String,
    pub preimage: Option<String>,
    pub invoice_expiry: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub domain: Option<String>,
    pub amount_received_sat: Option<i64>,
    pub wallet_kind: Option<WalletKind>,
    pub provider_metadata: Option<String>,
}
```

After all call sites are migrated, remove `user_pubkey` or make it optional.

For `handle_invoice_paid`, prefer payment hash lookup over user ownership. Ownership checks are provider-specific and should happen at webhook/API boundary before calling central paid logic.

### Provider Trait Details

Put this in `src/providers/mod.rs`.

```rust
#[derive(Debug, Clone)]
pub struct CreateInvoiceRequest {
    pub recipient: Recipient,
    pub amount_msat: u64,
    pub description_hash: [u8; 32],
    pub expiry_seconds: Option<u32>,
    pub wallet_kind: Option<WalletKind>,
}

#[derive(Debug, Clone)]
pub struct CreateInvoiceResponse {
    pub invoice: String,
}

#[derive(Debug, Clone)]
pub struct PaymentStatus {
    pub settled: bool,
    pub preimage: Option<String>,
    pub amount_received_sat: Option<i64>,
}
```

Provider implementations can parse Bolt11 at the route/service layer after invoice creation to avoid duplicating parsing.

Spark provider:

- Needs `Arc<spark_wallet::SparkWallet>`.
- Needs `include_spark_address`.
- Uses `recipient.spark.pubkey` as Spark receiver public key.
- Calls existing `create_lightning_invoice(amount_sat, Some(DescriptionHash(...)), Some(pubkey), expiry, include_spark_address)`.
- Rejects wallet modifiers with a provider error that routes convert to LNURL `ERROR`.

Blink provider:

- Needs `blink_client::Client`.
- Requires `recipient.blink`.
- Determines selected wallet:
  - explicit modifier if present.
  - otherwise `blink.default_wallet`.
- For BTC: call BTC mutation with `btc_wallet_id`.
- For USD: call USD-denominated mutation with `usd_wallet_id`.
- Amount sent to Blink mutations should be the LNURL callback amount in satoshis. Current server requires whole sats (`amount_msat % 1000 == 0`), so use `amount_msat / 1000`.
- Include the description hash if Blink mutation supports description hash input. If the exact schema field differs, adapt to Blink schema and keep LNURL metadata hash correctness.

### Blink GraphQL Documents

The exact fields must be confirmed against the checked-in Blink schema. The required operation names are product requirements:

- `LnInvoiceCreateOnBehalfOfRecipient`.
- `lnUsdInvoiceBtcDenominatedCreateOnBehalfOfRecipient`.
- `lnInvoicePaymentStatusByHash`.

Create operation documents with only fields needed by the server. The response must provide at minimum:

- Bolt11 invoice/payment request for create mutations.
- Payment status settled/paid boolean for status query.
- Preimage for settled invoices.

If using `graphql_client`, each operation should have:

- A `.graphql` operation file.
- A schema file path in the derive attribute.
- A Rust wrapper method that hides generated type names.

Client public API should look like:

```rust
pub struct BlinkClient {
    endpoint: String,
    http: reqwest::Client,
}

impl BlinkClient {
    pub fn new(endpoint: impl Into<String>) -> Self;

    pub async fn create_btc_invoice_on_behalf_of_recipient(
        &self,
        wallet_id: &str,
        amount_sat: u64,
        description_hash: [u8; 32],
        expiry_seconds: Option<u32>,
    ) -> Result<String, BlinkClientError>;

    pub async fn create_usd_btc_denominated_invoice_on_behalf_of_recipient(
        &self,
        wallet_id: &str,
        amount_sat: u64,
        description_hash: [u8; 32],
        expiry_seconds: Option<u32>,
    ) -> Result<String, BlinkClientError>;

    pub async fn invoice_payment_status_by_hash(
        &self,
        payment_hash: &str,
    ) -> Result<BlinkPaymentStatus, BlinkClientError>;
}
```

If Blink schema requires recipient/account id in addition to wallet id, include `blink_account_id` from `BlinkAccount`. Do not add authentication headers unless Blink public API changes.

### Route Changes In Detail

In `src/routes.rs`, avoid a full rewrite in one commit. Add small helper functions first:

- `resolve_public_recipient(state, host, raw_identifier) -> (Recipient, Option<WalletKind>, normalized_identifier_for_response)`.
- `lnurl_error(reason)` already exists; reuse it.
- `create_provider_invoice_for_account(...)` service helper can keep route size under control.

Spark registration route:

- Keep path `POST /lnurlpay/{pubkey}`.
- Keep `RegisterLnurlPayRequest` unchanged.
- Replace `sanitize_username`/old `validate_username` with Blink username normalization.
- Call new repository Spark registration method.
- Response remains:

```json
{
  "lnurl": "lnurlp://domain/lnurlp/username",
  "lightning_address": "username@domain"
}
```

Spark available route:

- Normalize identifier as username using Blink username rules.
- Query `account_identifiers` by domain/identifier.
- Return same JSON shape.

Spark unregister route:

- Keep path and body unchanged.
- Validate signature exactly as today.
- Delete Spark registration by domain/pubkey.

Spark recover route:

- Keep path and body unchanged.
- Validate signature exactly as today.
- Query Spark account by pubkey and domain.
- Return same JSON fields.

LNURL discovery:

- Replace `get_user_by_name` with account identifier lookup.
- If provider is Spark and wallet modifier was present, reject predictably. Recommended concrete behavior: discovery returns `404` for `alice+btc` when `alice` is Spark-owned, and callback returns LNURL `ERROR` if reached directly. Blink-owned identifiers support modifiers in both discovery and callback.
- Metadata should still be a JSON string compatible with existing `get_metadata` behavior. If `get_metadata` currently accepts `User`, create a provider-neutral version using `domain`, `identifier`, and `description`.

LNURL invoice callback:

- Keep whole-sat validation.
- Preserve comment validation and Nostr validation.
- Build description hash from zap event JSON when zapping, otherwise from metadata string.
- Dispatch to provider.
- Parse returned Bolt11 with `Bolt11Invoice::from_str`.
- Store invoice with provider/account/wallet fields.
- Store zaps/comments with account id when those tables are migrated.

Verify route:

- Load invoice.
- If invoice provider is `blink` and no preimage exists, call Blink status.
- If status returns preimage, call `handle_invoice_paid`.
- Return the same LUD-21 shape.

### Main State And Config Changes

Update `Args` in `src/main.rs`:

```rust
pub blink_graphql_endpoint: Option<String>,
pub internal_auth_clients: Option<String>,
```

Endpoint defaulting:

- If explicit `LNURL_BLINK_GRAPHQL_ENDPOINT` exists, use it.
- Otherwise default to `https://api.blink.sv/graphql`.
- Tests/e2e should override to mock server URL.

Update `State<DB>` in `src/state.rs`:

- Keep Spark wallet fields until Spark provider owns them.
- Add provider registry or explicit provider fields.
- Minimal approach:

```rust
pub spark_provider: Arc<providers::spark::SparkProvider>,
pub blink_provider: Arc<providers::blink::BlinkProvider>,
```

- Or use a service object that owns both providers and dispatches by `ProviderKind`.

Avoid making `State` generic over provider types; keep providers behind concrete structs or trait objects to reduce compile complexity.

### Route Registration Layout

Current `src/main.rs` builds one `Router` and applies the certificate `auth::auth` route layer only to the Spark management routes registered before `.route_layer(...)`. Public LNURL routes are registered after that layer and are unauthenticated.

Preserve this separation and add internal routes as a separate authenticated router. Recommended shape:

```rust
let spark_management_routes = Router::new()
    .route("/lnurlpay/available/{identifier}", get(LnurlServer::<DB>::available))
    .route("/lnurlpay/{pubkey}", post(LnurlServer::<DB>::register))
    .route("/lnurlpay/{pubkey}", delete(LnurlServer::<DB>::unregister))
    .route("/lnurlpay/{pubkey}/transfer", post(LnurlServer::<DB>::transfer))
    .route("/lnurlpay/{pubkey}/recover", post(LnurlServer::<DB>::recover))
    .route("/lnurlpay/{pubkey}/metadata", get(LnurlServer::<DB>::list_metadata))
    .route("/lnurlpay/{pubkey}/metadata/{payment_hash}/zap", post(LnurlServer::<DB>::publish_zap_receipt))
    .route("/lnurlpay/{pubkey}/invoice-paid", post(LnurlServer::<DB>::invoice_paid))
    .route("/lnurlpay/{pubkey}/invoices-paid", post(LnurlServer::<DB>::invoices_paid))
    .route_layer(middleware::from_fn_with_state(state.clone(), auth::auth::<DB>));

let internal_routes = Router::new()
    .route("/internal/blink/accounts", post(InternalServer::<DB>::register_blink_account))
    .route("/internal/accounts/by-identifier/{identifier}", get(InternalServer::<DB>::lookup_by_identifier))
    .route("/internal/blink/invoice-paid", post(InternalServer::<DB>::blink_invoice_paid))
    .route("/internal/identifiers/transfer-to-spark", post(InternalServer::<DB>::transfer_to_spark))
    .route_layer(middleware::from_fn_with_state(state.clone(), auth::internal_auth::<DB>));

let public_lnurl_routes = Router::new()
    .route("/.well-known/lnurlp/{identifier}", get(LnurlServer::<DB>::handle_lnurl_pay))
    .route("/lnurlp/{identifier}", get(LnurlServer::<DB>::handle_lnurl_pay))
    .route("/lnurlp/{identifier}/invoice", get(LnurlServer::<DB>::handle_invoice))
    .route("/verify/{payment_hash}", get(LnurlServer::<DB>::verify))
    .route("/webhook", post(LnurlServer::<DB>::webhook))
    .route("/health", get(|| async { StatusCode::OK }));

let server_router = Router::new()
    .merge(spark_management_routes)
    .merge(internal_routes)
    .merge(public_lnurl_routes)
    .layer(Extension(state));
```

This avoids accidentally putting public LNURL routes behind internal auth or leaving internal routes unauthenticated.

### Internal Auth Scope Details

Current `src/auth.rs` only verifies cert against CA and CRL. Enhance minimally:

- Keep existing behavior for routes using `.route_layer(middleware::from_fn_with_state(... auth::auth))`.
- Add a new middleware for internal routes that verifies cert and inserts an `InternalPrincipal` extension.
- Scope enforcement can initially be simple config matching by certificate subject or fingerprint.

Suggested config format for initial implementation:

```text
LNURL_INTERNAL_AUTH_CLIENTS=sha256fingerprint1:blink:accounts:create,blink:accounts:read,blink:settlements:write,blink:transfers:write;sha256fingerprint2:blink:accounts:read
```

If this is too much for first pass, require any valid cert for all internal APIs and add a `TODO` for scopes only if product approves. Preferred implementation is scoped from the start.

Do not require Spark message signatures for Blink internal APIs.

### Internal API Models

Add to `src/models.rs` or a new internal models module:

```rust
pub struct RegisterBlinkAccountRequest {
    pub domain: String,
    pub account_id: String,
    pub btc_wallet_id: String,
    pub usd_wallet_id: String,
    pub default_wallet: WalletKind,
    pub description: String,
    pub identifiers: Vec<RegisterIdentifier>,
}

pub struct RegisterIdentifier {
    pub r#type: IdentifierType,
    pub value: String,
}

pub struct BlinkInvoicePaidRequest {
    pub payment_hash: String,
    pub preimage: Option<String>,
    pub amount_sat: Option<i64>,
}

pub struct TransferIdentifierToSparkRequest {
    pub domain: String,
    pub identifier: String,
    pub target_spark_pubkey: String,
    pub description: String,
}
```

Serde names should match JSON camelCase where payloads above use camelCase. Use `#[serde(rename_all = "camelCase")]` for new internal models.

### Error And Status Code Rules

Public Spark compatibility routes:

- Preserve current HTTP status behavior where possible.
- Invalid username -> `400` with `"invalid username"` string JSON.
- Name/identifier conflict -> `409` with `"name already taken"` or existing-compatible text.
- Internal errors -> `500` with `"internal server error"`.

Internal Blink routes:

- Invalid body/identifier -> `400` with JSON error object or string. Prefer JSON object for new APIs.
- Unauthorized/no cert -> `401`.
- Authenticated but missing scope -> `403`.
- Blink account already exists -> `409`.
- Identifier already taken -> `409`.
- Not found -> `404`.

LNURL protocol routes:

- For application errors after discovery/callback, return LNURL `ERROR` JSON with HTTP 200 where current code does so.
- For unknown identifiers, keep current 404 behavior.

### External Webhook Compatibility

Current `src/webhook_notify.rs` emits `spark_payment_received`. Do not break existing Spark consumers.

Recommended implementation:

- Keep `spark_payment_received` for Spark invoices.
- Emit `lnurl_payment_received` for Blink invoices.
- If a provider-neutral payload is desired for Spark too, add it only as an opt-in config later.

Repository query `get_webhook_payloads` must return provider/account data. Add `provider` and `account_id` fields to `WebhookPayloadData`.

### E2E Mocking Strategy

Do not install Blink quickstart.

Use one of:

- A Wiremock container in `docker-compose.yml`/override for CI.
- A tiny local Rust/Node mock server started by `scripts/start-local-stack.sh`.
- A Bats helper that starts `wiremock` if available.

The mock must support GraphQL POSTs and return operation-specific JSON by inspecting `operationName` or the query string.

Minimum mocked responses:

- BTC create invoice returns a known Bolt11 invoice.
- USD create invoice returns a different known Bolt11 invoice.
- Status query returns unsettled.
- Status query returns settled with preimage.

Use generated test invoices with known preimages so `handle_invoice_paid` preimage verification passes. Existing test helpers in `src/invoice_paid.rs` show how valid Bolt11 invoices are generated for unit tests. For Bats, either hardcode valid regtest invoices generated by the test helper or add a small test utility binary to generate them.

### Verification Commands

Run these after implementation milestones:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Run Bats/e2e after server and mock setup is updated:

```sh
bats bats
```

If the repo uses Docker CI for e2e, also run the existing CI script or docker compose command after inspecting the current script paths.

### Suggested Commit/PR Breakdown

For a large implementation, split into small reviewable commits:

1. Identifier validation module and tests.
2. Account schema migrations and repository structs.
3. Repository methods for account lookup/registration with SQLite and Postgres tests.
4. Spark compatibility path migrated to new account model.
5. Provider trait plus Spark provider extraction.
6. `blink-client` crate with mock tests.
7. Blink provider and config.
8. Internal auth principal/scopes.
9. Blink registration and lookup APIs.
10. LNURL discovery/callback provider dispatch and wallet modifiers.
11. Blink verify/status fallback and webhook settlement.
12. Zaps/webhooks account-id migration.
13. Blink-to-Spark transfer.
14. Bats/e2e mock GraphQL coverage.

### Acceptance Criteria

Implementation is complete when:

- Existing Spark Bats tests still pass without changing their public API usage.
- Spark usernames are validated with Blink `checkedToUsername` rules.
- Blink account registration accepts one username and one phone for the same account.
- Blink account re-registration returns `409`.
- Identifier conflict across Spark and Blink returns `409`.
- Public lookup resolves Blink username and normalized phone identifiers.
- `identifier`, `identifier+btc`, and `identifier+usd` create invoices against the expected Blink wallet.
- Spark modifier usage is rejected predictably.
- Blink LUD-21 verify queries Blink status and stores preimage when settled.
- Blink webhook with preimage marks invoice paid.
- Blink webhook without preimage falls back to Blink status query.
- Zap receipts work for paid Blink invoices once preimage is known.
- Blink-to-Spark transfer moves only identifier ownership and new invoices use Spark.
- Unit, repository integration, and Bats/e2e tests cover the above.
