# Plan: v2 lnurlpay endpoints for Breez SDK 0.23

Unblocks [blinkbitcoin/blink-mobile#4257](https://github.com/blinkbitcoin/blink-mobile/pull/4257)
(Breez Spark SDK 0.22.0 → 0.23.1). That PR is marked "Do not merge before the
LNURL server is adapted" and has a blocking review on exactly that.

## Status

| Phase | State | Commit |
|---|---|---|
| 0 | Done: `lnurl-models` pinned at tag `0.23.1`, golden vectors, Host decision recorded (kept `axum_extra::Host`) | `chore(lnurlpay): pin Breez v2 signed-message format` |
| 1 | Done | `refactor(lnurlpay): verify signatures against candidate messages` |
| 2 | Done; still needs the staging probe and the #4257 run in 2h | `feat(lnurlpay): accept Breez SDK 0.23 breez-lnurl:v2 requests` |
| 3 | Server done; the blink-mobile change to sign `blink-lnurl:v1` is still open | `feat(lnurlpay): accept blink-lnurl:v1 for app-signed recover and mode` |
| 4 | Done | `feat(lnurlpay): act on each signed register, unregister and transfer once` |
| 5 | Not started: waiting on the product decision | — |
| 6 | Later: driven by the `blink_lnurl::legacy_signatures` counts | — |

Where the implementation differs from the text below:
- Signed `available` mirrors the unsigned route, which has no `require_spark_provider_enabled` gate. That keeps the two answers identical.
- `/mode` now resolves the request domain, which the `blink-lnurl:v1` message needs. A `/mode` request to a host outside the allow-list now gets a 404, as the other management routes already did.
- Phase 4 claims after the checks that refuse a request (`enhanced_mode_required`, ownership), so a refused request stays actionable.

## 1. Problem

The 0.23.1 client (`fa4d8c887`, "Scope LNURL signed messages to their route and
domain") changed three things on the wire. On 2026-09-17, staging and prod
answered all three wrongly: 404 on the new route and 400 on a v2 signature.

| Call | 0.22 client (what we serve today) | 0.23.1 client |
|---|---|---|
| Availability | `GET /lnurlpay/available/{username}`, unsigned | `POST /lnurlpay/{pubkey}/available`, body `{username, signature, timestamp}` |
| Register | `POST /lnurlpay/{pubkey}`, signs `{username}-{ts}` | same route, signs `breez-lnurl:v2\nregister\n<domain>\n<username>\n<sha256(description)>\n<ts>` |
| Unregister | `DELETE /lnurlpay/{pubkey}`, signs `{username}-{ts}` | signs `breez-lnurl:v2\nunregister\n<domain>\n<username>\n<ts>` |
| Recover | `POST …/recover`, signs `{pubkey}-{ts}` | signs `breez-lnurl:v2\nrecover\n<domain>\n<pubkey>\n<ts>` |
| Metadata | `GET …/metadata?signature&timestamp`, signs `{pubkey}-{ts}` | signature in `X-Breez-Signature` / `X-Breez-Timestamp` headers, signs `breez-lnurl:v2\nmetadata\n<domain>\n<pubkey>\n<ts>` |
| Transfer | signs `transfer:{username}-{to_pubkey}`, no timestamp | adds `timestamp`; A signs `transfer-from`, B signs `transfer-to` (with description hash) |

How the app breaks against today's server:
- **Lightning address registration is fully broken.**
  `useRegisterLightningAddress` → `checkLightningAddressAvailable` gets a 404.
  The bare catch at `use-register-lightning-address.ts:64-65` turns that into
  `UNKNOWN_ERROR`.
- **SDK recover fails.** It runs on fresh install and on restore, and returns
  400. `getLightningAddress` callers swallow or report the error.
- **SDK metadata sync fails** with 400, so zaps, comments and preimages stop
  syncing.

The app's own hand-signed calls in `app/self-custodial/lnurl-server-mode.ts`
are a separate constraint:
- `/mode` signs `mode:{mode}:{pubkey}-{ts}`.
- `/recover` signs `{pubkey}-{ts}`.

Both stay on the legacy format in the PR. **They cannot move to
`breez-lnurl:v2`**, because 0.23's public `signMessage` refuses any message
starting with `breez-lnurl:` (`reject_reserved_namespace`, core
`sdk/api.rs`). So the server has to verify legacy messages on `/recover` and
`/mode` for as long as the app sends them. A Blink-owned replacement format is
covered in Phase 3.

## 2. Ground truth: format and semantics

- **Byte spec.** `lnurl-models/src/signed_message.rs` at tag `0.23.1`. Its
  `golden_vectors` test is the protocol ("a wire break rather than a test to
  update").
  - Fields are joined by `\n`. The first field is `breez-lnurl:v2`.
  - The description enters as lowercase-hex `sha256` of its exact bytes, with
    no trimming.
  - `VALIDITY_SECS = 600`, which matches our `ACCEPTABLE_TIME_DIFF_SECS`.
- **Signature.** ECDSA over `sha256(message)`, DER, hex-encoded. This is the
  same primitive our `validate()` already uses through
  `spark_wallet::verify_message` → `verify_signature_ecdsa`. Only the message
  bytes change.
- **Signed domain.** The client builds it with `parse_domain`: the URL host,
  lowercased, plus the port only if it is non-default. The app sets
  `lnurlDomain` to `blink.sv` on mainnet and `staging.blink.sv` on
  regtest/staging, so the signed domain is exactly those strings. We already
  resolve those values today: `sanitize_domain` returns `blink.sv` for
  register, which is why addresses come back as `user@blink.sv`.
- **Username.** The SDK signs `sanitize_username(input)` (trim + lowercase) and
  sends that same string. We must build the message from the username exactly
  as received after the same sanitization. We must not rebuild it from any
  further Blink canonicalization.
- **How upstream migrated** (the Breez server, `lnurl/src/routes.rs` @ 0.23.1).
  We mirror this:
  - Each route has an ordered list of *candidates*: v2 first, then the legacy
    form. The first one that verifies wins.
  - Legacy verifies are counted per route and logged once a minute.
  - `available_for_pubkey` is v2-only: the route is new, so no legacy form
    exists.
  - Recover and metadata claim nothing because they are reads.
  - Register, unregister and transfer *claim* the statement in
    `used_signed_messages`. A replay gets 409.
  - Released usernames are held for the pubkey that released them
    (`released_names`), so signed `available` can answer "free for you".
  - A failed verify returns `invalid signature for domain '<domain>'`, so
    Host/proxy mistakes can be diagnosed.
  - Metadata responses carry `Cache-Control: no-store, private`.

## 3. Phases

Phases 1–2 are the blocker for #4257. Ship them as one PR to staging and probe
them with the app PR build. Phase 3 follows soon after. Phases 4–5 are
independent hardening and policy work. Phase 6 is a later cleanup.

### Phase 0: Decisions and groundwork (½ day)

1. **Share the message builders. Do not re-type them.**
   - Add `lnurl-models = { git = "https://github.com/breez/spark-sdk", tag = "0.23.1", package = "lnurl-models" }`.
   - It depends only on `serde` and `sha2`. Our pinned spark-sdk rev `2c80c32`
     is an ancestor of `0.23.1`, so nothing else moves.
   - Fallback: vendor `signed_message.rs` into `src/signed_message.rs` and keep
     its `golden_vectors` test verbatim.
   - Either way, the golden vectors run in our CI.
2. **Host resolution policy.**
   - We use `axum_extra::extract::Host`, which prefers `Forwarded` /
     `X-Forwarded-Host` over `Host`.
   - Upstream dropped it (#1066) for a plain `Host` extractor.
   - Now that the domain is part of what is signed, the value we resolve must
     equal the client's URL authority.
   - **Action:** confirm what the staging/prod ingress forwards for
     `https://blink.sv/lnurlpay/...` and `https://staging.blink.sv/...`.
   - Keep `axum_extra::Host` if it yields `blink.sv`. Otherwise switch to the
     upstream extractor. Record the decision in `docs/ARCHITECTURE.md`.
3. **Product call on released-name holds (Phase 5).** This is not a blocker.
   Until Phase 5 lands, signed `available` gives the same answer as unsigned
   `available`, which is correct while no holds exist.

### Phase 1: Candidate-based verifier (refactor, no behavior change) (1 day)

Files: `src/routes/account.rs`, `src/routes/mod.rs`, a new `src/routes/signed.rs`.

1. Split `validate()` into three steps:
   - `parse_signed_request(pubkey, signature) -> (PublicKey, Signature)`
   - `timestamp_is_fresh(ts)` (keep the 600 s window and reuse
     `signed_message::VALIDITY_SECS`)
   - `verify_candidates(&pk, &sig, &[Candidate], domain) -> &Candidate`
2. Define `Candidate { message, route: SignedRoute, legacy: bool }`, with
   `SignedRoute ∈ {Register, Unregister, Recover, Metadata, Transfer, Available, Mode}`.
3. Add the legacy counter: an `AtomicU64` per route plus a 60 s reporter task
   logging on target `blink_lnurl::legacy_signatures`, started from `main.rs`.
   This is the signal Phase 6 waits on.
4. Rewrite every existing caller as a one-element legacy candidate list. This
   covers register, unregister, recover, `list_metadata`, mode, zap,
   invoice-paid and invoices-paid.
5. Return `invalid signature for domain '<d>'` on a verify miss. Leave every
   other error body as it is.
6. **Exit:** all existing unit and bats tests pass unchanged.

### Phase 2: v2 endpoints (the unblocker) (2–3 days)

**2a. `POST /lnurlpay/{pubkey}/available` (new)**
- Wire it in `src/main.rs` behind the same `auth` route layer as the other
  `/lnurlpay/*` routes.
  - It does not conflict with `/lnurlpay/available/{identifier}`: axum gives the
    static segment priority, and a pubkey is never the literal `available`.
- Request model `CheckUsernameAvailableRequest { username, signature, timestamp }`.
- Handler `available_for_pubkey` in `src/routes/lnurl_pay.rs`:
  1. Sanitize the username, then validate it with the Blink username rules.
  2. Run `sanitize_domain`, then parse, then the freshness check.
  3. Verify against v2 only: `signed_message::available(domain, pk, username, ts)`.
  4. Resolve the name the same way as the unsigned `available` (including
     Blink custodial identifiers and phone identifiers).
  5. Reply `{available}`.
- Keep `GET /lnurlpay/available/{identifier}` for 0.22 clients (old app
  versions in the field).
- Respect `require_spark_provider_enabled`, as register does.

**2b. Register / unregister** (`src/routes/account.rs`)
- Register candidates:
  1. `signed_message::register(domain, username, description, ts)`
  2. legacy `{username}-{ts}`
- Unregister candidates:
  1. `signed_message::unregister(domain, username, ts)`
  2. legacy `{username}-{ts}`
- Resolve the domain *before* verifying, because v2 names it.
- `validate_description` must not trim, because the description is hashed
  byte-exact.
- Behavior stays the same, including the `Anon` → `enhanced_mode_required`
  check. The 0.23.1 client treats a 404 on unregister as success.

**2c. Recover**
- Candidates:
  1. `signed_message::recover(domain, pk, ts)`
  2. legacy `{raw_pubkey}-{ts}` (the app's hand-signed call, and 0.22 SDKs)
- **The response shape depends on which candidate matched:**
  - **v2 (the SDK):** follow upstream semantics.
    - A registered username returns 200 with the full
      `{lnurl, lightning_address, username, description}` (plus `mode`; serde
      ignores unknown fields).
    - **No username returns 404, even if a mode is stored.**
    - The SDK's `RecoverLnurlPayResponse` makes all four fields required. Today
      a mode-only account returns `200 {mode}`, and the SDK fails to
      deserialize it. That is a latent bug, and this phase fixes it.
  - **legacy:** keep today's Blink-extended response, `mode` with optional
    address fields. `lnurl-server-mode.ts` reads `{mode}` from it.
- Keep `spawn_country_evidence_refresh` on both paths.

**2d. Metadata**
- Add `HeaderMap` and the `metadata_credentials` logic:
  - A present `X-Breez-Signature` / `X-Breez-Timestamp` header wins.
  - A malformed header is a 400, not a fall-through.
  - The query parameters remain the fallback.
- Make `ListMetadataRequest.signature` and `.timestamp` `Option`.
- Candidates:
  1. `signed_message::metadata(domain, pk, ts)`
  2. legacy `{raw_pubkey}-{ts}`
- Respond with `Cache-Control: no-store, private`.
- CORS already uses `allow_headers(Any)`. Confirm the preflight passes in a
  test.

**2e. Transfer** (SDK API only; the app does not call it, but 0.23.1 SDKs may)
- Add an optional `timestamp` to `TransferLnurlPayRequest`.
- `Some(ts)`: run the freshness check, then verify v2 only.
  - A signs `transfer_from(domain, username, from, to, ts)`.
  - B signs `transfer_to(domain, username, from, to, description, ts)`.
  - A timestamp outside the window gets the distinct error "transfer
    authorization is expired or not yet valid".
- `None`: keep legacy `transfer:{username}-{to_pubkey}` for both signatures.

**2f. Unchanged on purpose**
- `/mode`, zap receipt, invoice-paid and invoices-paid stay legacy-only for now.
  - 0.23.1's SDK does not call zap or invoice-paid.
  - `/mode` is app-signed and handled in Phase 3.
  - All of them still go through the Phase 1 candidate path, so their legacy
    traffic is counted.

**2g. Tests**
- Unit (`src/routes/test_support.rs` + per-route tests):
  - v2 accepted on every route.
  - Legacy still accepted where listed.
  - v2 signed for `other.example` is rejected with the domain-naming error.
  - A signature for route X fails on route Y.
  - Recover returns 404 for a v2 request on a mode-only account and 200
    `{mode}` for a legacy request on the same account.
  - A metadata header wins over the query, and a malformed header is a 400.
  - Signed `available` agrees with unsigned `available`.
- Golden vectors: either inherited from the dependency, or a copied test that
  asserts our builders produce the upstream bytes.
- E2E signer: `spark-client::build_auth_payload` (`crates/spark-client/src/client.rs`)
  and `src/bin/e2e_auth.rs` emit v2 signatures alongside the legacy ones,
  including `available`, so bats can drive both.
- Bats (`bats/spark_endpoints.bats`):
  - Duplicate "register recover and unregister" as a v2 flow over
    `POST …/available`.
  - Add a header-signed metadata call.
  - Keep the legacy flow as the 0.22 regression.

**2h. Rollout**
1. Merge and deploy to staging (`staging.blink.sv`).
2. Repeat the 2026-09-17 probe:
   - `POST /lnurlpay/{pk}/available` returns 200.
   - A v2 register returns 200.
3. Run the #4257 build end to end on staging: new user, backup, claim username,
   restore wallet (SDK recover + app mode recover), metadata sync.
4. Run the current store build (0.22) against the same server, to prove legacy
   still works.
5. Deploy to prod, then unblock #4257.
6. Update `docs/API.md`: the route table, the signed-message section and the
   header credentials.

### Phase 3: Blink-scoped messages for app-signed routes (1–2 days server, plus an app PR)

This addresses review finding 2 on #4257:
- The legacy recover message `{pubkey}-{ts}` is byte-identical to the legacy
  metadata message.
- So any captured `/recover` signature works as a `/metadata` credential
  (preimages included) for 600 s.
- The mode message is prefixed, but it is not domain-scoped.

1. Define a Blink namespace outside `breez-lnurl:`, so `signMessage` will sign
   it: `blink-lnurl:v1\n<route>\n<domain>\n<pubkey>\n…\n<ts>`.
   - `recover`: `blink-lnurl:v1\nrecover\n<domain>\n<pubkey>\n<ts>`
   - `mode`: `blink-lnurl:v1\nmode\n<domain>\n<pubkey>\n<mode>\n<ts>`
   - Put the builders and their own golden vectors in `src/signed_message.rs`
     (Blink). Mirror the vectors in an app unit test.
2. Server candidates:
   - recover: v2 → blink v1 → legacy.
   - mode: blink v1 → legacy.
   - Blink v1 recover returns the Blink-extended response, the same as legacy.
3. App follow-up PR: `lnurl-server-mode.ts` signs blink v1, and the comment at
   :104-109 is reworded as the reviewers asked.
4. Once legacy counters for recover and metadata reach zero (Phase 6), the
   cross-route replay is closed. Until then, Phase 4 does not help, because
   reads are not claimed.

### Phase 4: Single-use statements (1–2 days)

Today a captured legacy register signature `{username}-{ts}` also verifies as
an unregister for 10 minutes, because both routes sign the same bytes. Nothing
stops replay of mutating requests within the window.

1. Add migration `used_signed_messages(statement_hash PK, route, expires_at, created_at)`
   plus an index on `expires_at`, for both `migrations/postgres` and
   `migrations/sqlite`.
2. Repository: `claim_signed_message(hash, route, expires_at) -> bool` and
   `delete_expired_signed_messages(now)`. Start the pruner task in `main.rs`.
3. `statement_hash = sha256(pubkey_hex || 0x00 || message)`. It hashes the
   statement, not the signature bytes, because signatures are malleable.
4. Claim on register, unregister and transfer, *after* the domain and input
   checks and *before* acting.
   - Inside the transaction for transfer.
   - Expiry is `ts + 600`, or never for the untimestamped legacy transfer.
5. A replay returns 409 "signature has already been used". Clients re-sign on
   retry, as the 0.23.1 SDK does.
6. `/mode` keeps its monotonic `mode_last_timestamp` anchor. Claiming there is
   optional.

### Phase 5: Released-name holds (product decision first) (2–3 days)

This is the upstream behavior that gives signed `available` its meaning. A name
a pubkey gives up (by unregistering, re-registering a different name, or
transferring away) is held for that pubkey, so payers' old addresses never reach
a stranger.

Blink-specific questions to settle before building:
- Does a hold block Blink Core's internal `create_internal_blink_account` and
  `transfer-to-spark` for that name?
- How do holds interact with phone identifiers?
- Should holds lapse? Upstream reserves `reclaimable_from` for this but never
  writes it.

Implementation if approved:
1. Migration `released_names(domain, name, pubkey, released_at, reclaimable_from)`.
2. Repository `name_status(domain, name, asking_pubkey) -> Free | Taken | Reserved`.
3. `upsert_spark_registration`, `delete_spark_registration` and
   `transfer_identifier` write and clear holds in the same transaction.
4. Unsigned `available` passes `None`, so holds read as unavailable. Signed
   `available` passes the pubkey.
5. Register returns 409 "name is reserved".

### Phase 6: Legacy sunset (later)

- Watch the `blink_lnurl::legacy_signatures` counts.
- Mobile users update slowly, so gate on the app's minimum supported version as
  well as on the counts.
- Once a route reads zero across deployments for an agreed window:
  - Drop its legacy candidate.
  - Make `ListMetadataRequest` header-only.
  - Make transfer `timestamp` required.
  - Then remove `GET /lnurlpay/available/{identifier}`.

## 4. Risks and checks

- **Host mismatch.** This is the most likely way v2 fails in prod. It shows up
  as 400 `invalid signature for domain 'X'`. Verify it on staging, in Phase 0,
  step 2.
- **Description bytes.** Any trim or normalize step between the request and
  storage breaks register verification. Add a test with leading and trailing
  spaces.
- **Username canonicalization drift.** If `canonical_spark_username` ever
  differs from `trim + lowercase` for an accepted name, the v2 message must
  still be built from the sanitized wire value.
- **The recover response split.** This is a behavior change for v2 callers on
  mode-only accounts: 200 becomes 404. That matches upstream and fixes SDK
  deserialization. Legacy callers (the app) are unaffected.
- **Old app versions.** 0.22 clients keep the unsigned GET and legacy signatures
  throughout Phases 1–5.

## 5. Order of work

| PR | Contents | Unblocks |
|---|---|---|
| 1 | Phase 0 + 1 + 2 | blink-mobile#4257 |
| 2 | Phase 3 (server) | app PR for blink v1 recover/mode, review finding 2 |
| 3 | Phase 4 | replay hardening |
| 4 | Phase 5 | "name held for you" UX (after product sign-off) |
| — | Phase 6 | legacy removal, driven by counters |
