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

@test "blink: default usd and explicit btc wallet selection use mocked graphql" {
  create_blink_account "blinkdefaultusd10" "Blink default USD wallet" "usd" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkdefaultusd10")"
  callback_url="$(json_get "$discovery" '.callback')"

  run blink_lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.pr'
  payment_hash="$(json_get "$output" '.verify' | awk -F/ '{print $NF}')"
  [ "$(invoice_wallet_kind "${payment_hash}")" = "usd" ]

  create_blink_account "blinkbtcoverride10" "Blink BTC override wallet" "usd" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkbtcoverride10+btc")"
  callback_url="$(json_get "$discovery" '.callback')"

  run blink_lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.pr'
  payment_hash="$(json_get "$output" '.verify' | awk -F/ '{print $NF}')"
  [ "$(invoice_wallet_kind "${payment_hash}")" = "btc" ]
  [ "$(account_identifier_exists "blinkbtcoverride10+btc")" = "false" ]
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

@test "blink: settlement webhook with supplied preimage marks invoice paid" {
  create_blink_account "blinksettlepreimage10" "Blink settlement preimage wallet" "btc" "btc-wallet-paid-fallback-preimage10" >/dev/null
  discovery="$(blink_lnurl_discovery "blinksettlepreimage10")"
  invoice="$(blink_lnurl_callback "$(json_get "$discovery" '.callback')" "1000")"
  payment_hash="$(json_get "$invoice" '.verify' | awk -F/ '{print $NF}')"

  run blink_settlement_notify "$payment_hash" "0909090909090909090909090909090909090909090909090909090909090909"
  [ "$status" -eq 0 ]
  [ "$(invoice_has_preimage "${payment_hash}")" = "true" ]
}

@test "blink: settlement webhook without preimage falls back to payment status" {
  create_blink_account "blinksettlefallback10" "Blink settlement fallback wallet" "btc" "btc-wallet-paid-fallback-hooks" >/dev/null
  discovery="$(blink_lnurl_discovery "blinksettlefallback10")"
  invoice="$(blink_lnurl_callback "$(json_get "$discovery" '.callback')" "1000")"
  payment_hash="$(json_get "$invoice" '.verify' | awk -F/ '{print $NF}')"

  run blink_settlement_notify_without_preimage "$payment_hash"
  [ "$status" -eq 0 ]
  [ "$(invoice_has_preimage "${payment_hash}")" = "true" ]
}

@test "blink: verify unsettled returns false without persisting preimage" {
  create_blink_account "blinkunsettled10" "Blink unsettled wallet" "btc" "btc-wallet-unsettled10" >/dev/null
  discovery="$(blink_lnurl_discovery "blinkunsettled10")"
  invoice="$(blink_lnurl_callback "$(json_get "$discovery" '.callback')" "1000")"
  verify_url="$(json_get "$invoice" '.verify')"

  run curl -fsS "$verify_url"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.status' 'OK'
  assert_json_equals "$output" '.settled' 'false'
  assert_json_equals "$output" '.preimage' 'null'
  payment_hash="${verify_url##*/}"
  [ "$(invoice_has_preimage "${payment_hash}")" = "false" ]
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

@test "blink: multi-identifier account registration resolves username and phone to same account" {
  response="$(create_blink_account_multi "acct-blinkmulti10" "Multi identifier wallet" "btc" "btc-wallet-blinkmulti10" "usd-wallet-blinkmulti10" "blinkmulti10" "+573005871212")"
  assert_json_equals "$response" '.provider' 'blink'
  assert_json_equals "$response" '.blink_account_id' 'acct-blinkmulti10'
  account_id="$(json_get "$response" '.account_id')"

  for local_part in "blinkmulti10" "+573005871212" "573005871212" "00573005871212"; do
    discovery="$(blink_lnurl_discovery "${local_part}")"
    assert_json_equals "$discovery" '.tag' 'payRequest'
  done

  username_lookup="$(internal_identifier_lookup "blinkmulti10")"
  phone_lookup="$(internal_identifier_lookup "+573005871212")"
  assert_json_equals "$username_lookup" '.provider' 'blink'
  assert_json_equals "$phone_lookup" '.provider' 'blink'
  assert_json_equals "$username_lookup" '.account_id' "$account_id"
  assert_json_equals "$phone_lookup" '.account_id' "$account_id"
  assert_json_equals "$username_lookup" '.provider_details.blink_account_id' 'acct-blinkmulti10'
  assert_json_equals "$phone_lookup" '.provider_details.blink_account_id' 'acct-blinkmulti10'
}

@test "blink: internal lookup resolves canonical identifiers and wallet modifiers" {
  create_blink_account_multi "acct-blinklookup10" "Lookup wallet" "btc" "btc-wallet-blinklookup10" "usd-wallet-blinklookup10" "blinklookup10" >/dev/null

  base_lookup="$(internal_identifier_lookup "blinklookup10")"
  usd_lookup="$(internal_identifier_lookup "blinklookup10+usd")"
  btc_lookup="$(internal_identifier_lookup "blinklookup10+btc")"
  account_id="$(json_get "$base_lookup" '.account_id')"

  assert_json_equals "$base_lookup" '.provider' 'blink'
  assert_json_equals "$base_lookup" '.requested_wallet' 'null'
  assert_json_equals "$usd_lookup" '.account_id' "$account_id"
  assert_json_equals "$usd_lookup" '.requested_wallet' 'usd'
  assert_json_equals "$btc_lookup" '.account_id' "$account_id"
  assert_json_equals "$btc_lookup" '.requested_wallet' 'btc'
  assert_json_equals "$btc_lookup" '.provider_details.default_wallet' 'btc'
}

@test "blink: registration rejects same blink_account_id and Spark-owned identifiers" {
  create_blink_account_multi "acct-reregister10" "Original Blink wallet" "btc" "btc-wallet-reregister10" "usd-wallet-reregister10" "reregister10a" >/dev/null
  same_account_body="$(create_blink_account_body "acct-reregister10" "btc-wallet-reregister10b" "usd-wallet-reregister10b" "btc" "Second Blink wallet" "reregister10b")"

  response="$(post_internal_blink_account_status_body "$same_account_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "409" ]
  assert_json_equals "$body" '.error' 'blink_account_exists'

  register_user "crossprovider10" "localhost:8080" "Spark-owned wallet" >/dev/null
  conflict_body="$(create_blink_account_body "acct-crossprovider10" "btc-wallet-crossprovider10" "usd-wallet-crossprovider10" "btc" "Conflicting Blink wallet" "crossprovider10")"
  response="$(post_internal_blink_account_status_body "$conflict_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "409" ]
  assert_json_equals "$body" '.error' 'identifier_conflict'
}

@test "blink: internal registration validates default wallet and identifiers" {
  missing_body="$(create_blink_account_body "acct-missingdefault10" "btc-wallet-missingdefault10" "usd-wallet-missingdefault10" "btc" "Missing default wallet" "missingdefault10" | jq -c 'del(.default_wallet)')"
  response="$(post_internal_blink_account_status_body "$missing_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "422" ]
  [[ "$body" == *"Failed to deserialize the JSON body into the target type"* ]]
  [[ "$body" == *"missing field `default_wallet`"* ]]

  invalid_wallet_body="$(create_blink_account_body "acct-invalidwallet10" "btc-wallet-invalidwallet10" "usd-wallet-invalidwallet10" "eur" "Invalid wallet" "invalidwallet10")"
  response="$(post_internal_blink_account_status_body "$invalid_wallet_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "400" ]
  assert_json_equals "$body" '.error' 'invalid_request'

  invalid_identifier_body="$(create_blink_account_body "acct-invalididentifier10" "btc-wallet-invalididentifier10" "usd-wallet-invalididentifier10" "btc" "Invalid identifier" "not valid")"
  response="$(post_internal_blink_account_status_body "$invalid_identifier_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "400" ]
  assert_json_equals "$body" '.error' 'invalid_identifier'

  invalid_phone_body="$(create_blink_account_body "acct-invalidphone10" "btc-wallet-invalidphone10" "usd-wallet-invalidphone10" "btc" "Invalid phone" "12345")"
  response="$(post_internal_blink_account_status_body "$invalid_phone_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "400" ]
  assert_json_equals "$body" '.error' 'invalid_identifier'

  wallet_modifier_body="$(create_blink_account_body "acct-modifier10" "btc-wallet-modifier10" "usd-wallet-modifier10" "btc" "Wallet modifier" "alice+btc")"
  response="$(post_internal_blink_account_status_body "$wallet_modifier_body" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "400" ]
  assert_json_equals "$body" '.error' 'wallet_modifier_not_allowed'
}

@test "blink: internal auth rejects missing invalid and wrong-scope tokens on critical routes" {
  account_body="$(create_blink_account_body "acct-authnegative10" "btc-wallet-authnegative10" "usd-wallet-authnegative10" "btc" "Auth negative wallet" "authnegative10")"
  settlement_body="$(jq -cn --arg payment_hash "authnegativehash10" '{eventType:"receive.lightning",transaction:{status:"success",initiationVia:{paymentHash:$payment_hash},settlementVia:{type:"SettlementViaIntraLedger"}}}')"

  response="$(post_internal_blink_account_status_body "$account_body")"
  [ "${response##*$'\n'}" = "401" ]
  response="$(post_internal_blink_account_status_body "$account_body" "not-a-jwt")"
  [ "${response##*$'\n'}" = "401" ]
  response="$(post_internal_blink_account_status_body "$account_body" "$(internal_test_token "accounts:read")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "403" ]
  assert_json_equals "$body" '.error' 'forbidden'

  response="$(internal_identifier_lookup_status_body "blinkmulti10")"
  [ "${response##*$'\n'}" = "401" ]
  response="$(internal_identifier_lookup_status_body "blinkmulti10" "not-a-jwt")"
  [ "${response##*$'\n'}" = "401" ]
  response="$(internal_identifier_lookup_status_body "blinkmulti10" "$(internal_test_token "blink:accounts:create")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "403" ]
  assert_json_equals "$body" '.error' 'forbidden'

  response="$(blink_settlement_notify_status_body "$settlement_body")"
  [ "${response##*$'\n'}" = "401" ]
  response="$(blink_settlement_notify_status_body "$settlement_body" "not-a-jwt")"
  [ "${response##*$'\n'}" = "401" ]
  response="$(blink_settlement_notify_status_body "$settlement_body" "$(internal_test_token "accounts:read")")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "403" ]
  assert_json_equals "$body" '.error' 'forbidden'
}

@test "blink: phone identifier registration resolves through public discovery" {
  create_blink_account_multi "acct-phone10" "Phone wallet" "btc" \
    "btc-wallet-phone10" "usd-wallet-phone10" "+573005871213" >/dev/null

  for local_part in "+573005871213" "573005871213" "00573005871213"; do
    run blink_lnurl_discovery "${local_part}"
    [ "$status" -eq 0 ]
    assert_json_equals "$output" '.tag' 'payRequest'
  done
}
