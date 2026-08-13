# API Reference

This service exposes public LNURL-pay and Lightning Address endpoints, Spark-compatible account-management endpoints, Blink internal account endpoints, and payment webhook receivers.

## Authentication

The API uses different authentication mechanisms by route group:

- **Public LNURL endpoints** (`/.well-known/lnurlp/*`, `/lnurlp/*`, `/verify/*`, `/health`) do not require credentials.
- **Spark-compatible management endpoints** under `/lnurlpay/{pubkey}` verify Spark signatures in the JSON body or query string. The signed message is usually `{message}-{timestamp}` and timestamps must be within 600 seconds of server time (`src/routes/account.rs`, `src/routes/mod.rs`). If `LNURL_CA_CERT` is configured, these routes also require an `Authorization: Bearer <base64-der-client-certificate>` header validated against the configured CA and optional CRL (`src/auth.rs`).
- **Internal Blink endpoints** under `/internal/*` require `Authorization: Bearer <jwt>`. Tokens must be RS256 JWTs with a matching `kid` from the configured JWKS, expected issuer, expected audience, `exp`, and `nbf` claims (`src/internal_auth.rs`). Required scopes are listed per endpoint below.
- **Spark SSP webhook** `/webhook` requires the `X-Spark-Signature` header. The value must be a hex-encoded HMAC-SHA256 of the raw request body using the persisted `webhook_secret` setting (`src/routes/webhook.rs`).
- **Blink invoice webhook** `/webhook/blink` is a public receiver endpoint for Blink invoice callbacks; it validates the payment request hash when `paymentRequest` is present and settles only stored Blink invoices (`src/routes/webhook.rs`).

## Endpoints Overview

| Method | Path | Description | Auth Required |
|---|---|---|---|
| `GET` | `/.well-known/lnurlp/{identifier}` | Return an LNURL-pay metadata response for a Lightning Address identifier. | No |
| `GET` | `/lnurlp/{identifier}` | Return an LNURL-pay metadata response. Supports `+btc` and `+usd` wallet modifiers for Blink identifiers. | No |
| `GET` | `/lnurlp/{identifier}/invoice` | Create a BOLT11 invoice for an LNURL payment callback. | No |
| `GET` | `/lnurlp/{domain}/{identifier}/invoice` | Create a BOLT11 invoice for an LNURL payment callback using the path domain. Used when `LNURL_CALLBACK_DOMAIN` is configured. | No |
| `GET` | `/verify/{payment_hash}` | Return LUD-21 settlement status, preimage, and invoice for a stored payment hash. | No |
| `GET` | `/health` | Readiness check returning HTTP 200. | No |
| `GET` | `/lnurlpay/available/{identifier}` | Check whether a Spark username is available on the request host domain. | Optional client certificate if `LNURL_CA_CERT` is configured |
| `POST` | `/lnurlpay/{pubkey}` | Register a Spark LNURL username. | Spark signature; optional client certificate |
| `DELETE` | `/lnurlpay/{pubkey}` | Unregister a Spark LNURL username. | Spark signature; optional client certificate |
| `POST` | `/lnurlpay/{pubkey}/transfer` | Transfer a Spark username from one Spark pubkey to another. | Spark signatures; optional client certificate |
| `POST` | `/lnurlpay/{pubkey}/recover` | Recover the mode, and the registered LNURL and Lightning Address, for a Spark pubkey. | Spark signature; optional client certificate |
| `POST` | `/lnurlpay/{pubkey}/mode` | Set the region-determination mode (`enhanced` or `anon`) for a Spark pubkey, creating the account on first contact. | Spark signature; optional client certificate; per-IP rate limit |
| `GET` | `/lnurlpay/{pubkey}/metadata` | List sender comments, zap requests, zap receipts, preimages, and update times for a Spark pubkey. | Spark signature query parameters; optional client certificate |
| `POST` | `/lnurlpay/{pubkey}/metadata/{payment_hash}/zap` | Publish and persist a NIP-57 zap receipt for a stored zap request. | Spark signature; optional client certificate |
| `POST` | `/lnurlpay/{pubkey}/invoice-paid` | Legacy single-invoice paid notification with a preimage. | Spark signature; optional client certificate |
| `POST` | `/lnurlpay/{pubkey}/invoices-paid` | Batch paid-invoice notification with up to 100 invoices. | Spark signature; optional client certificate |
| `POST` | `/internal/blink/accounts` | Create a Blink-backed account and its identifiers. | Internal JWT with `blink:accounts:create` |
| `PATCH` | `/internal/blink/accounts/{blink_account_id}` | Update a Blink-backed account default wallet. | Internal JWT with `blink:accounts:update` |
| `GET` | `/internal/domains/{domain}/identifiers/{identifier}` | Resolve an identifier to provider-neutral account details. | Internal JWT with `blink:accounts:read` |
| `POST` | `/internal/identifiers/transfer-to-spark` | Transfer a Blink identifier to a Spark pubkey. | Internal JWT with `blink:transfers:write` |
| `POST` | `/webhook` | Receive Spark Service Provider payment notifications. | `X-Spark-Signature` HMAC |
| `POST` | `/webhook/blink` | Receive Blink invoice `PAID` or `EXPIRED` notifications. | No |

## Request/Response Formats

### Public LNURL metadata

`GET /lnurlp/{identifier}` and `GET /.well-known/lnurlp/{identifier}` return the LUD-06 pay metadata shape:

```json
{
  "callback": "https://example.com/lnurlp/alice/invoice",
  "maxSendable": 4000000000,
  "minSendable": 1000,
  "tag": "payRequest",
  "metadata": "[[\"text/plain\",\"Alice wallet\"],[\"text/identifier\",\"alice@example.com\"]]",
  "commentAllowed": 255,
  "allowsNostr": true,
  "nostrPubkey": "<x-only-nostr-pubkey>"
}
```

`allowsNostr` and `nostrPubkey` are included only when the server has Nostr keys configured.

If `LNURL_CALLBACK_DOMAIN` is configured, the advertised callback uses that host and includes the original recipient domain in the path so multi-domain identifiers remain unambiguous:

```json
{
  "callback": "https://callback.example.com/lnurlp/example.com/alice/invoice"
}
```

### Public invoice callback

`GET /lnurlp/{identifier}/invoice` and `GET /lnurlp/{domain}/{identifier}/invoice` accept these query parameters:

| Parameter | Required | Description |
|---|---:|---|
| `amount` | Yes | Amount in millisatoshis. It must be a whole-satoshi amount and within `minSendable`/`maxSendable`. |
| `comment` | No | Sender comment. The maximum trimmed length is 255 characters. |
| `nostr` | No | NIP-57 zap request JSON. |
| `expiry` | No | Requested invoice expiry. Blink BTC allows up to 86,400 seconds; Blink USD allows up to 300 seconds. |

Successful responses contain exactly `pr`, `routes`, and `verify`:

```json
{
  "pr": "lnbc...",
  "routes": [],
  "verify": "https://example.com/verify/<payment_hash>"
}
```

When `LNURL_CALLBACK_DOMAIN` is configured, the advertised `verify` URL uses that host as well.

### Spark-compatible management requests

Registration request:

```json
{
  "username": "alice",
  "signature": "<der-signature-hex>",
  "timestamp": 1710000000,
  "description": "Alice wallet"
}
```

Registration response:

```json
{
  "lnurl": "lnurlp://example.com/lnurlp/alice",
  "lightning_address": "alice@example.com"
}
```

Batch invoice-paid request:

```json
{
  "signature": "<der-signature-hex>",
  "timestamp": 1710000000,
  "invoices": [
    {
      "preimage": "<preimage-hex>",
      "invoice": "lnbc..."
    }
  ]
}
```

Recover response. `mode` is always present; `null` means the account has never chosen one. The address fields are absent for an account that has a mode but no username:

```json
{
  "lnurl": "lnurlp://example.com/lnurlp/alice",
  "lightning_address": "alice@example.com",
  "username": "alice",
  "description": "Alice wallet",
  "mode": "enhanced"
}
```

Mode request. The signed message is `mode:{mode}:{pubkey}-{timestamp}`; `timestamp` must be within 600 seconds of server time, at most 30 seconds ahead of it, AND strictly newer than the last accepted mode request for this pubkey. Re-sending the exact request that was last accepted (same mode, same timestamp — a retry after a dropped response) succeeds without changing anything; any other older request is refused:

```json
{
  "mode": "enhanced",
  "signature": "<der-signature-hex>",
  "timestamp": 1710000000
}
```

Mode response:

```json
{
  "mode": "enhanced"
}
```

Setting `enhanced` resolves the request IP (from `x-real-ip`) to a country and stores it as compliance evidence; setting `anon` clears that evidence in the same statement and stops invoice issuance for the account's Lightning Address. Registering a username and receiving a user-initiated transfer are both refused while the stored mode is `anon`. The server-initiated migration transfer is the deliberate exception: it completes even for an `anon` destination, and the address stays dormant (no invoices are minted) until the account switches to `enhanced` — failing the migration would be the harsher outcome for a state only the account holder can create. The accepted timestamp is stored verbatim as the monotonic anchor; a timestamp more than 30 seconds ahead of server time is refused with `mode_timestamp_in_future` rather than clamped — a clamped anchor would sit below the timestamp of the request that wrote it, letting a captured request be replayed past a later mode switch. The refusal caps any fast-clock cross-device lockout at 30 seconds.

Successful `DELETE`, `/invoice-paid`, and `/invoices-paid` responses have an empty body.

### Internal Blink account creation

`POST /internal/blink/accounts` request:

```json
{
  "domain": "example.com",
  "blink_account_id": "blink_account_123",
  "btc_wallet_id": "btc_wallet_123",
  "usd_wallet_id": "usd_wallet_123",
  "default_wallet": "usd",
  "description": "Blink account",
  "identifiers": ["alice", "+573005871212"]
}
```

Response:

```json
{
  "account_id": "acct_blink_...",
  "provider": "blink",
  "blink_account_id": "blink_account_123",
  "btc_wallet_id": "btc_wallet_123",
  "usd_wallet_id": "usd_wallet_123",
  "default_wallet": "usd",
  "domain": "example.com",
  "identifiers": [
    {
      "identifier": "alice",
      "kind": "username",
      "description": "Blink account"
    }
  ]
}
```

### Internal Blink account default-wallet update

`PATCH /internal/blink/accounts/{blink_account_id}` request:

```json
{
  "default_wallet": "usd"
}
```

Response:

```json
{
  "account_id": "acct_blink_...",
  "provider": "blink",
  "blink_account_id": "blink_account_123",
  "default_wallet": "usd"
}
```

Only `btc` and `usd` are accepted. The route updates only `blink_accounts.default_wallet`.

Errors include `400 invalid_request`, `403 forbidden`, `404 not_found`, and `503 provider_disabled`.

### Internal identifier lookup

`GET /internal/domains/{domain}/identifiers/{identifier}` returns provider-neutral account data:

```json
{
  "provider": "blink",
  "account_id": "acct_blink_...",
  "domain": "example.com",
  "identifier": "alice",
  "identifier_kind": "username",
  "description": "Blink account",
  "requested_wallet": "usd",
  "provider_details": {
    "blink_account_id": "blink_account_123",
    "btc_wallet_id": "btc_wallet_123",
    "usd_wallet_id": "usd_wallet_123",
    "default_wallet": "usd"
  }
}
```

For Spark-backed identifiers, `provider_details.spark_pubkey` is populated instead of Blink wallet fields.

### Webhooks

Spark SSP `/webhook` body fields used by the server:

```json
{
  "type": "SPARK_LIGHTNING_RECEIVE_FINISHED",
  "payment_preimage": "<preimage-hex>",
  "receiver_identity_public_key": "<spark-pubkey-hex>",
  "htlc_amount": {
    "value": 1000,
    "unit": "MILLISATOSHI"
  }
}
```

Blink `/webhook/blink` body:

```json
{
  "paymentHash": "<payment-hash-hex>",
  "paymentPreimage": "<preimage-hex>",
  "paymentRequest": "lnbc...",
  "status": "PAID"
}
```

`status` may be `PAID` or `EXPIRED`. `paymentPreimage` and `paymentRequest` are optional in the Rust DTO, but paid settlement needs either a supplied preimage or a successful Blink status lookup.

## Error Codes

| Status | Shape | Meaning |
|---:|---|---|
| `200` | `{ "status": "ERROR", "reason": "..." }` | Public LNURL protocol errors such as missing amount, unsupported wallet, invalid zap request, expired policy, or invoice creation failure. |
| `400` | JSON string or `{ "error": "..." }` | Invalid usernames, invalid signatures, invalid timestamps, `mode_timestamp_in_future` for a mode request more than 30 seconds ahead of server time, malformed JSON, invalid preimages/invoices, invalid internal request fields, or zap receipt validation failures. |
| `401` | Empty body or JSON string | Missing/invalid client certificate, missing/invalid internal bearer JWT, or invalid Spark webhook signature. |
| `403` | `{ "error": "forbidden" }` or `{ "error": "unauthorized" }` | Internal JWT lacks the required scope, or a zap receipt is being published by the wrong Spark pubkey. |
| `404` | JSON string, `{ "error": "not_found" }`, or empty string | User, invoice, zap, account, or identifier was not found. |
| `409` | JSON string or `{ "error": "identifier_conflict" }` | Username or identifier conflict, invalid provider ownership for transfer, `enhanced_mode_required` when a username is claimed or received while the stored mode is `anon`, or `mode_request_not_newer` when a mode request would roll the mode back. |
| `429` | JSON string `"rate_limited"` | More mode requests than `LNURL_MODE_REQUESTS_PER_IP_PER_MINUTE` from one client IP, or a mode request with no trusted `x-real-ip` outside `DEPLOYMENT_ENV=local`. |
| `500` | JSON string or `{ "error": "internal_server_error" }` | Repository failure, provider state failure, malformed configured keys/certificates, or unexpected invoice/provider state. |

The public LUD-21 verify endpoint always returns JSON with `status`: `OK` or `ERROR`:

```json
{
  "status": "OK",
  "settled": true,
  "preimage": "<preimage-hex>",
  "pr": "lnbc..."
}
```

## Rate Limits

`POST /lnurlpay/{pubkey}/mode` is limited per client IP (`x-real-ip`) by `LNURL_MODE_REQUESTS_PER_IP_PER_MINUTE`, and the same budget also covers the paid country lookup that `POST /lnurlpay/{pubkey}` and `POST /lnurlpay/{pubkey}/recover` perform for an Enhanced account: over budget, those two routes still succeed, they just leave the stored country at its previous value.

Outside `DEPLOYMENT_ENV=local`, a request carrying no trusted `x-real-ip` has no budget at all — the mode route returns `429` and the country lookup is skipped. Deployment must therefore guarantee the edge sets that header. The counter is in-process, so the effective budget is per replica. No other route has application-level rate limiting. The Axum router enforces a maximum request body size of 1,000,000 bytes (`src/main.rs`).
