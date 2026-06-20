#!/usr/bin/env bats

load "helpers/common.bash"
load "helpers/assertions.bash"

setup_file() {
  export LNURL_INTERNAL_JWKS_PATH="${ROOT_DIR}/tests/fixtures/internal_auth_jwks.json"
  export LNURL_INTERNAL_JWT_ISSUER="https://issuer.internal.test"
  export LNURL_INTERNAL_JWT_AUDIENCE="lnurl-server.internal.test"
  start_stack
}

teardown_file() {
  stop_stack
}

setup() {
  register_user "alice" "localhost:8080" "Alice test wallet" >/dev/null
}

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

internal_test_token() {
  local scope="${1:?scope is required}"
  local header
  local claims
  local signing_input
  local signature

  header="$(printf '%s' '{"alg":"RS256","kid":"blink-internal-test-key","typ":"JWT"}' | base64url)"
  claims="$(jq -cn --arg scope "${scope}" '{sub:"blink-core-test-service",iss:"https://issuer.internal.test",aud:"lnurl-server.internal.test",exp:4102444800,nbf:1700000000,scope:$scope}' | base64url)"
  signing_input="${header}.${claims}"
  signature="$(printf '%s' "${signing_input}" | openssl dgst -sha256 -sign "${ROOT_DIR}/tests/fixtures/internal_auth_private.pem" -binary | base64url)"
  printf '%s.%s\n' "${signing_input}" "${signature}"
}

seed_post_transfer_fixture() {
  local account_id="${1:?account id is required}"
  local identifier="${2:?identifier is required}"
  local historical_hash="${3:?historical payment hash is required}"

  docker compose exec -T postgres psql -U user -d lnurl \
    -c "INSERT INTO accounts(account_id, provider, created_at, updated_at) VALUES ('${account_id}', 'blink', 0, 0) ON CONFLICT (account_id) DO NOTHING; INSERT INTO blink_accounts(account_id, blink_account_id, btc_wallet_id, usd_wallet_id, default_wallet, created_at, updated_at) VALUES ('${account_id}', '${account_id}_blink', '${account_id}_btc_wallet', '${account_id}_usd_wallet', 'btc', 0, 0) ON CONFLICT (account_id) DO NOTHING; INSERT INTO account_identifiers(account_id, domain, identifier, identifier_kind, description, created_at, updated_at) VALUES ('${account_id}', 'localhost:8080', '${identifier}', 'username', 'Historical Blink wallet', 0, 0) ON CONFLICT (domain, identifier) DO NOTHING; INSERT INTO invoices(payment_hash, user_pubkey, invoice, preimage, invoice_expiry, created_at, updated_at, domain, amount_received_sat, account_id, provider, wallet_kind, wallet_id, provider_payment_hash) VALUES ('${historical_hash}', 'blink_historical_pubkey', 'lnbc1historical', NULL, 4102444800000, 1, 1, 'localhost:8080', NULL, '${account_id}', 'blink', 'btc', '${account_id}_btc_wallet', '${historical_hash}') ON CONFLICT (payment_hash) DO NOTHING" >/dev/null
}

internal_transfer_to_spark() {
  local token="${1:?token is required}"
  local identifier="${2:?identifier is required}"
  local destination_pubkey="${3:?destination pubkey is required}"

  curl -sS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${token}" \
    --data "{\"domain\":\"localhost:8080\",\"identifier\":\"${identifier}\",\"destination_spark_pubkey\":\"${destination_pubkey}\",\"description\":\"Post-transfer Spark wallet\"}" \
    --write-out $'\n%{http_code}' \
    "${BASE_URL}/internal/identifiers/transfer-to-spark"
}

invoice_provider_account() {
  local payment_hash="${1:?payment hash is required}"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT provider || ':' || account_id FROM invoices WHERE payment_hash = '${payment_hash}'"
}

latest_invoice_provider_account_for_spark_pubkey() {
  local spark_pubkey="${1:?spark pubkey is required}"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT i.provider || ':' || i.account_id FROM invoices i JOIN spark_accounts s ON s.account_id = i.account_id WHERE i.domain = 'localhost:8080' AND s.pubkey = '${spark_pubkey}' ORDER BY i.created_at DESC LIMIT 1"
}

@test "lnurl: discovery returns payRequest" {
  run lnurl_discovery "alice" "localhost:8080"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.tag' 'payRequest'
  assert_json_equals "$output" '.minSendable' '1000'
  assert_json_nonempty "$output" '.maxSendable'
  assert_json_nonempty "$output" '.metadata'
  assert_json_equals "$output" '.callback' 'http://localhost:8080/lnurlp/alice/invoice'
  assert_json_equals "$output" '.commentAllowed' '255'
}

@test "lnurl: callback returns invoice and verify URL" {
  discovery="$(lnurl_discovery "alice" "localhost:8080")"
  callback_url="$(json_get "$discovery" '.callback')"

  run lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]

  assert_json_nonempty "$output" '.pr'
  assert_json_nonempty "$output" '.verify'
  assert_json_equals "$output" '.verify | startswith("http://localhost:8080/verify/")' 'true'
  assert_json_equals "$output" '.routes | length' '0'
  assert_json_absent_or_not_contains "$output" '.status' 'ERROR'
}

@test "lnurl: post-transfer identifier resolves to Spark while historical Blink invoice stays Blink-owned" {
  historical_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  seed_post_transfer_fixture "acct_blink_lnurl_history" "posttransfer" "${historical_hash}"
  destination_pubkey="$(json_get "$(auth_payload "posttransfer")" '.to_pubkey')"
  token="$(internal_test_token "blink:transfers:write")"

  response="$(internal_transfer_to_spark "${token}" "posttransfer" "${destination_pubkey}")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "${code}" = "200" ]
  assert_json_equals "${body}" '.provider' 'spark'

  run lnurl_discovery "posttransfer" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.tag' 'payRequest'
  assert_json_equals "$output" '.callback' 'http://localhost:8080/lnurlp/posttransfer/invoice'
  callback_url="$(json_get "$output" '.callback')"

  run lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.pr'
  assert_json_nonempty "$output" '.verify'
  assert_json_equals "$output" '.routes | length' '0'
  assert_json_absent_or_not_contains "$output" '.status' 'ERROR'

  [ "$(invoice_provider_account "${historical_hash}")" = "blink:acct_blink_lnurl_history" ]
  new_owner="$(latest_invoice_provider_account_for_spark_pubkey "${destination_pubkey}")"
  [[ "${new_owner}" == spark:* ]]
  [ "${new_owner}" != "spark:acct_blink_lnurl_history" ]
}

@test "lnurl: btc wallet modifier preserves Spark discovery and callback happy path" {
  for alias in "alice+BTC" "alice+btc"; do
    run lnurl_discovery "$alias" "localhost:8080"
    [ "$status" -eq 0 ]

    assert_json_equals "$output" '.tag' 'payRequest'
    assert_json_equals "$output" '.callback' 'http://localhost:8080/lnurlp/alice+btc/invoice'
    assert_json_nonempty "$output" '.metadata'
    assert_json_equals "$output" '.commentAllowed' '255'

    callback_url="$(json_get "$output" '.callback')"
    run lnurl_callback "$callback_url" "1000"
    [ "$status" -eq 0 ]
    assert_json_nonempty "$output" '.pr'
    assert_json_nonempty "$output" '.verify'
    assert_json_equals "$output" '.verify | startswith("http://localhost:8080/verify/")' 'true'
    assert_json_equals "$output" '.routes | length' '0'
    assert_json_absent_or_not_contains "$output" '.status' 'ERROR'
  done
}

@test "lnurl: usd wallet modifier returns Spark unsupported-wallet LNURL error from discovery or returned callback" {
  run lnurl_discovery "alice+usd" "localhost:8080"
  [ "$status" -eq 0 ]

  if [ "$(json_get "$output" '.status // empty')" = "ERROR" ]; then
    assert_json_equals "$output" '.reason' 'unsupported wallet'
    assert_json_absent_or_not_contains "$output" '.pr' 'ln'
  else
    assert_json_equals "$output" '.tag' 'payRequest'
    assert_json_equals "$output" '.callback' 'http://localhost:8080/lnurlp/alice+usd/invoice'
    assert_json_nonempty "$output" '.metadata'
    assert_json_equals "$output" '.commentAllowed' '255'

    callback_url="$(json_get "$output" '.callback')"
    [[ "$callback_url" == *"/lnurlp/alice+usd/invoice" ]]

    run lnurl_callback "$callback_url" "1000"
    [ "$status" -eq 0 ]
    assert_json_equals "$output" '.status' 'ERROR'
    assert_json_equals "$output" '.reason' 'unsupported wallet'
    assert_json_absent_or_not_contains "$output" '.pr' 'ln'
  fi
}

@test "lnurl: unknown and chained wallet modifiers fail before Spark lookup" {
  for invalid in "alice+eur" "alice+btc+usd" "alice+btc+btc"; do
    response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/${invalid}" "localhost:8080")"
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"

    [ "$code" = "200" ]
    assert_json_equals "$body" '.status' 'ERROR'
    assert_json_equals "$body" '.reason' 'invalid identifier'

    response="$(http_status_body "GET" "${BASE_URL}/lnurlp/${invalid}/invoice?amount=1000" "localhost:8080")"
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"

    [ "$code" = "200" ]
    assert_json_equals "$body" '.status' 'ERROR'
    assert_json_equals "$body" '.reason' 'invalid identifier'
  done
}

@test "lnurl: valid phone-like identifiers return LNURL error while invalid ones do not fall back to numeric legacy usernames" {
  insert_legacy_user "573005871212" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000001" "Numeric legacy wallet"
  insert_legacy_user "12345" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000002" "Invalid phone legacy wallet"

  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/573005871212" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "200" ]
  assert_json_equals "$body" '.status' 'ERROR'
  assert_json_equals "$body" '.reason' "Couldn't find user '573005871212'."

  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/12345" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "404" ]
  [ "$body" = '""' ]
}

@test "lnurl: legacy non-modifier Spark names still resolve but plus legacy names do not" {
  insert_legacy_user "legacy.name" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000003" "Legacy dotted wallet"
  insert_legacy_user "legacy+eur" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000004" "Legacy plus wallet"

  run lnurl_discovery "legacy.name" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.tag' 'payRequest'
  assert_json_equals "$output" '.callback' 'http://localhost:8080/lnurlp/legacy.name/invoice'

  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/legacy+eur" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "200" ]
  assert_json_equals "$body" '.status' 'ERROR'
  assert_json_equals "$body" '.reason' 'invalid identifier'
}

@test "lnurl: verify returns unsettled invoice" {
  discovery="$(lnurl_discovery "alice" "localhost:8080")"
  callback_url="$(json_get "$discovery" '.callback')"
  invoice="$(lnurl_callback "$callback_url" "1000")"
  verify_url="$(json_get "$invoice" '.verify')"

  run curl -fsS "$verify_url"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.status' 'OK'
  assert_json_equals "$output" '.settled' 'false'
  assert_json_nonempty "$output" '.pr'
}

@test "lnurl: missing amount returns ERROR" {
  discovery="$(lnurl_discovery "alice" "localhost:8080")"
  callback_url="$(json_get "$discovery" '.callback')"

  run lnurl_callback "$callback_url"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.status' 'ERROR'
  assert_json_equals "$output" '.reason' 'missing amount'
  assert_json_absent_or_not_contains "$output" '.pr' 'ln'
}

@test "lnurl: non-whole-sat amount returns ERROR" {
  discovery="$(lnurl_discovery "alice" "localhost:8080")"
  callback_url="$(json_get "$discovery" '.callback')"

  run lnurl_callback "$callback_url" "1001"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.status' 'ERROR'
  assert_json_equals "$output" '.reason' 'amount must be a whole sat amount'
  assert_json_absent_or_not_contains "$output" '.pr' 'ln'
}

@test "lnurl: unknown user returns LNURL error" {
  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/missing" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "200" ]
  assert_json_equals "$body" '.status' 'ERROR'
  assert_json_equals "$body" '.reason' "Couldn't find user 'missing'."
}

@test "lnurl: disallowed domain returns 404" {
  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/alice" "evil.example.com")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "404" ]
  [ "$body" = '""' ]
}

@test "lnurl: callback unknown user returns 404 with empty body" {
  response="$(http_status_body "GET" "${BASE_URL}/lnurlp/missing/invoice?amount=1000" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "404" ]
  [ "$body" = '""' ]
}
