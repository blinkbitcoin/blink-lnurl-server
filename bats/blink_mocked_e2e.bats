#!/usr/bin/env bats

load "helpers/common.bash"
load "helpers/assertions.bash"

setup_file() {
  export LNURL_INTERNAL_JWKS_PATH="${ROOT_DIR}/tests/fixtures/internal_auth_jwks.json"
  export LNURL_INTERNAL_JWT_ISSUER="https://issuer.internal.test"
  export LNURL_INTERNAL_JWT_AUDIENCE="lnurl-server.internal.test"
  export LNURL_POSTGRES_PORT="${LNURL_POSTGRES_PORT:-25432}"
  export LNURL_NSEC="0101010101010101010101010101010101010101010101010101010101010101"
  start_blink_graphql_mock
  start_stack
}

teardown_file() {
  stop_stack
  stop_blink_graphql_mock
}

@test "blink: account registration and conflict" {
  run create_blink_account "blinkreg" "Blink registration wallet" "btc"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.provider' 'blink'

  run create_blink_account_status "blinkreg" "Duplicate Blink wallet" "btc"
  [ "$status" -eq 0 ]
  [ "$output" = "409" ]
}

@test "blink: discovery and btc callback use mocked graphql" {
  create_blink_account "blinkbtc" "Blink BTC wallet" "btc" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkbtc")"
  callback_url="$(json_get "$discovery" '.callback')"

  run blink_lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.pr'
  assert_json_nonempty "$output" '.verify'
  payment_hash="$(json_get "$output" '.verify' | awk -F/ '{print $NF}')"
  [ "$(invoice_account_provider "${payment_hash}")" = "blink" ]
}

@test "blink: usd callback uses mocked graphql" {
  create_blink_account "blinkusd" "Blink USD wallet" "btc" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkusd+usd")"
  callback_url="$(json_get "$discovery" '.callback')"

  run blink_lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.pr'
  payment_hash="$(json_get "$output" '.verify' | awk -F/ '{print $NF}')"
  [ "$(invoice_wallet_kind "${payment_hash}")" = "usd" ]
}

@test "blink: verify settlement fallback marks paid" {
  create_blink_account "blinkpaid" "Blink paid fallback wallet" "btc" "btc-wallet-paid-fallback" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkpaid")"
  invoice="$(blink_lnurl_callback "$(json_get "$discovery" '.callback')" "1000")"
  verify_url="$(json_get "$invoice" '.verify')"

  run curl -fsS "$verify_url"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.status' 'OK'
  assert_json_equals "$output" '.settled' 'true'
  payment_hash="${verify_url##*/}"
  [ "$(invoice_has_preimage "${payment_hash}")" = "true" ]
}

@test "blink: zap and webhook side effects use provider-neutral ownership" {
  create_blink_account "blinkhooks" "Blink side effects wallet" "btc" "btc-wallet-paid-fallback-hooks" >/dev/null
  configure_domain_webhook "localhost:8080" "http://127.0.0.1:9/webhook" "test-secret"
  # Domain webhook configs are refreshed by the running server on its normal poll interval.
  sleep 65
  discovery="$(blink_lnurl_discovery "blinkhooks")"
  assert_json_equals "$discovery" '.allowsNostr' 'true'
  assert_json_nonempty "$discovery" '.nostrPubkey'
  zap_request="$(zap_request_for_discovery "$discovery" "1000")"
  invoice="$(blink_lnurl_callback "$(json_get "$discovery" '.callback')" "1000" "$zap_request")"
  verify_url="$(json_get "$invoice" '.verify')"
  curl -fsS "$verify_url" >/dev/null
  payment_hash="${verify_url##*/}"

  [ "$(invoice_has_preimage "${payment_hash}")" = "true" ]
  [ "$(invoice_account_provider "${payment_hash}")" = "blink" ]
  [ "$(zap_side_effect_state "${payment_hash}")" = "1:present" ]
  [ "$(zap_receipt_side_effect_state "${payment_hash}")" = "present" ]
  [ "$(webhook_delivery_count_for_payment_hash "${payment_hash}")" -ge 1 ]
  webhook_payload="$(webhook_delivery_payload_for_payment_hash "${payment_hash}")"
  assert_json_equals "$webhook_payload" '.template' 'payment_received'
  assert_json_equals "$webhook_payload" '.data.payment_hash' "$payment_hash"
  assert_json_equals "$webhook_payload" '.data.lightning_address' 'blinkhooks@localhost:8080'
  assert_json_absent_or_not_contains "$webhook_payload" '.data' 'provider'
  assert_json_absent_or_not_contains "$webhook_payload" '.data' 'account_id'
  assert_json_absent_or_not_contains "$webhook_payload" '.data' 'blink_account_id'
  assert_json_absent_or_not_contains "$webhook_payload" '.data' 'btc_wallet_id'
  assert_json_absent_or_not_contains "$webhook_payload" '.data' 'usd_wallet_id'
  assert_json_absent_or_not_contains "$webhook_payload" '.data' 'user_pubkey'
}

@test "blink: transfer to spark preserves history and moves new invoices" {
  create_blink_account "blinkmove" "Blink transfer wallet" "btc" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkmove")"
  invoice="$(blink_lnurl_callback "$(json_get "$discovery" '.callback')" "1000")"
  historical_hash="$(json_get "$invoice" '.verify' | awk -F/ '{print $NF}')"
  destination_pubkey="$(json_get "$(auth_payload "blinkmove")" '.to_pubkey')"

  run transfer_blink_identifier_to_spark "blinkmove" "${destination_pubkey}" "Moved Spark wallet"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.provider' 'spark'
  [ "$(identifier_owner_provider "blinkmove")" = "spark" ]
  [ "$(invoice_account_provider "${historical_hash}")" = "blink" ]
}

@test "blink: phone identifier registration resolves through public discovery" {
  create_blink_account "+573005871212" "Blink phone wallet" "btc" >/dev/null

  run blink_lnurl_discovery "+573005871212"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.tag' 'payRequest'
}
