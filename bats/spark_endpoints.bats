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

seed_blink_transfer_fixture() {
  local account_id="${1:?account id is required}"
  local moved_identifier="${2:?moved identifier is required}"
  local untouched_identifier="${3:?untouched identifier is required}"
  local description="${4:-Blink transfer source}"

  docker compose exec -T postgres psql -U user -d lnurl \
    -c "INSERT INTO accounts(account_id, provider, created_at, updated_at) VALUES ('${account_id}', 'blink', 0, 0) ON CONFLICT (account_id) DO NOTHING; INSERT INTO blink_accounts(account_id, blink_account_id, btc_wallet_id, usd_wallet_id, default_wallet, created_at, updated_at) VALUES ('${account_id}', '${account_id}_blink', '${account_id}_btc_wallet', '${account_id}_usd_wallet', 'btc', 0, 0) ON CONFLICT (account_id) DO NOTHING; INSERT INTO account_identifiers(account_id, domain, identifier, identifier_kind, description, created_at, updated_at) VALUES ('${account_id}', 'localhost:8080', '${moved_identifier}', 'username', '${description}', 0, 0), ('${account_id}', 'localhost:8080', '${untouched_identifier}', 'username', 'Untouched Blink wallet', 0, 0) ON CONFLICT (domain, identifier) DO NOTHING" >/dev/null
}

internal_transfer_to_spark() {
  local token="${1:?token is required}"
  local identifier="${2:?identifier is required}"
  local destination_pubkey="${3:?destination pubkey is required}"
  local description="${4:?description is required}"

  curl -sS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${token}" \
    --data "{\"domain\":\"localhost:8080\",\"identifier\":\"${identifier}\",\"destination_spark_pubkey\":\"${destination_pubkey}\",\"description\":\"${description}\"}" \
    --write-out $'\n%{http_code}' \
    "${BASE_URL}/internal/identifiers/transfer-to-spark"
}

identifier_owner_provider() {
  local identifier="${1:?identifier is required}"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT a.provider FROM account_identifiers ai JOIN accounts a ON a.account_id = ai.account_id WHERE ai.domain = 'localhost:8080' AND ai.identifier = '${identifier}'"
}

identifier_spark_pubkey() {
  local identifier="${1:?identifier is required}"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT s.pubkey FROM account_identifiers ai JOIN spark_accounts s ON s.account_id = ai.account_id WHERE ai.domain = 'localhost:8080' AND ai.identifier = '${identifier}'"
}

@test "spark: register recover and unregister" {
  run username_available "authuser" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'true'

  run register_user "authuser" "localhost:8080" "Authenticated test wallet"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.lightning_address' 'authuser@localhost:8080'

  run username_available "authuser" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'false'

  run recover_user "authuser" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.username' 'authuser'
  assert_json_equals "$output" '.description' 'Authenticated test wallet'

  run unregister_user "authuser" "localhost:8080"
  [ "$status" -eq 0 ]

  run username_available "authuser" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'true'
}

@test "spark: availability and duplicate registration preserve Spark contract" {
  run username_available "dupeuser" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'true'

  run register_user "dupeuser" "localhost:8080" "Duplicate baseline wallet"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.lightning_address' 'dupeuser@localhost:8080'

  auth="$(auth_payload "dupeuser")"
  pubkey="$(json_get "$auth" '.to_pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.to_register_signature')"
  data="{\"username\":\"dupeuser\",\"signature\":\"${signature}\",\"timestamp\":${timestamp},\"description\":\"Duplicate baseline wallet\"}"

  response="$(http_status_body "POST" "${BASE_URL}/lnurlpay/${pubkey}" "localhost:8080" "$data")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "409" ]
  [ "$body" = '"name already taken"' ]
}

@test "spark: transfer remains compatible after cross-provider transfer support" {
  run register_user "transferuser" "localhost:8080" "Transfer source wallet"
  [ "$status" -eq 0 ]

  auth="$(auth_payload "transferuser")"
  to_pubkey="$(json_get "$auth" '.to_pubkey')"

  run transfer_user "transferuser" "localhost:8080" "Transfer target wallet"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.lightning_address' 'transferuser@localhost:8080'
  assert_json_equals "$output" '.lnurl' 'lnurlp://localhost:8080/lnurlp/transferuser'

  old_recover_signature="$(json_get "$auth" '.recover_signature')"
  timestamp="$(json_get "$auth" '.timestamp')"
  from_pubkey="$(json_get "$auth" '.pubkey')"
  run recover_user_status "localhost:8080" "$old_recover_signature" "$timestamp" "$from_pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "404" ]

  new_recover_signature="$(json_get "$auth" '.to_recover_signature')"
  run curl -fsS \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --data "{\"signature\":\"${new_recover_signature}\",\"timestamp\":${timestamp}}" \
    "${BASE_URL}/lnurlpay/${to_pubkey}/recover"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.username' 'transferuser'
  assert_json_equals "$output" '.description' 'Transfer target wallet'
}

@test "spark: internal transfer-to-spark requires transfer scope" {
  seed_blink_transfer_fixture "acct_blink_bats_scope" "scopemove" "scopestay" "Scoped Blink wallet"
  destination_pubkey="$(json_get "$(auth_payload "scopemove")" '.to_pubkey')"
  token="$(internal_test_token "accounts:read")"

  response="$(internal_transfer_to_spark "${token}" "scopemove" "${destination_pubkey}" "Should not move")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "${code}" = "403" ]
  assert_json_equals "${body}" '.error' 'forbidden'
  [ "$(identifier_owner_provider "scopemove")" = "blink" ]
}

@test "spark: internal transfer-to-spark moves one Blink identifier to Spark" {
  seed_blink_transfer_fixture "acct_blink_bats_success" "internalmove" "internalstay" "Internal Blink wallet"
  destination_pubkey="$(json_get "$(auth_payload "internalmove")" '.to_pubkey')"
  token="$(internal_test_token "transfer:write")"

  response="$(internal_transfer_to_spark "${token}" "internalmove" "${destination_pubkey}" "Internal Spark wallet")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "${code}" = "200" ]
  assert_json_equals "${body}" '.domain' 'localhost:8080'
  assert_json_equals "${body}" '.identifier' 'internalmove'
  assert_json_equals "${body}" '.provider' 'spark'
  assert_json_equals "${body}" '.spark_pubkey' "${destination_pubkey}"
  assert_json_equals "${body}" '.lightning_address' 'internalmove@localhost:8080'
  assert_json_equals "${body}" '.lnurl' 'lnurlp://localhost:8080/lnurlp/internalmove'
  [ "$(identifier_owner_provider "internalmove")" = "spark" ]
  [ "$(identifier_spark_pubkey "internalmove")" = "${destination_pubkey}" ]
  [ "$(identifier_owner_provider "internalstay")" = "blink" ]
}

@test "spark: transfer replaces destination's previous Spark alias" {
  run register_user "transferreplace" "localhost:8080" "Transfer replacement source"
  [ "$status" -eq 0 ]

  destination_auth="$(auth_payload "destinationalias")"
  destination_pubkey="$(json_get "$destination_auth" '.to_pubkey')"
  destination_timestamp="$(json_get "$destination_auth" '.timestamp')"
  destination_signature="$(json_get "$destination_auth" '.to_register_signature')"
  destination_data="{\"username\":\"destinationalias\",\"signature\":\"${destination_signature}\",\"timestamp\":${destination_timestamp},\"description\":\"Destination old alias\"}"

  response="$(http_status_body "POST" "${BASE_URL}/lnurlpay/${destination_pubkey}" "localhost:8080" "$destination_data")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [ "$code" = "200" ]
  assert_json_equals "$body" '.lightning_address' 'destinationalias@localhost:8080'

  run transfer_user "transferreplace" "localhost:8080" "Transfer replacement target"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.lightning_address' 'transferreplace@localhost:8080'

  run username_available "destinationalias" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'true'

  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/destinationalias" "localhost:8080")"
  code="${response##*$'\n'}"
  [ "$code" = "404" ]

  transfer_auth="$(auth_payload "transferreplace")"
  timestamp="$(json_get "$transfer_auth" '.timestamp')"
  new_recover_signature="$(json_get "$transfer_auth" '.to_recover_signature')"
  run curl -fsS \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --data "{\"signature\":\"${new_recover_signature}\",\"timestamp\":${timestamp}}" \
    "${BASE_URL}/lnurlpay/${destination_pubkey}/recover"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.username' 'transferreplace'
  assert_json_equals "$output" '.description' 'Transfer replacement target'

  run lnurl_discovery "transferreplace" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.callback'
}

@test "spark: re-registration removes stale Spark aliases and preserves recover" {
  run register_user "oldalias" "localhost:8080" "Old alias wallet"
  [ "$status" -eq 0 ]

  auth="$(auth_payload "newalias")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.register_signature')"
  data="{\"username\":\"newalias\",\"signature\":\"${signature}\",\"timestamp\":${timestamp},\"description\":\"New alias wallet\"}"

  response="$(http_status_body "POST" "${BASE_URL}/lnurlpay/${pubkey}" "localhost:8080" "$data")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "200" ]
  assert_json_equals "$body" '.lightning_address' 'newalias@localhost:8080'

  run username_available "oldalias" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'true'

  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/oldalias" "localhost:8080")"
  code="${response##*$'\n'}"
  [ "$code" = "404" ]

  run recover_user "newalias" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.username' 'newalias'
  assert_json_equals "$output" '.description' 'New alias wallet'
}

@test "spark: unregister deletes only the signed Spark identifier" {
  run register_user "deleteone" "localhost:8080" "Delete one wallet"
  [ "$status" -eq 0 ]

  auth="$(auth_payload "deleteone")"
  pubkey="$(json_get "$auth" '.pubkey')"
  docker compose exec -T postgres psql -U user -d lnurl \
    -c "INSERT INTO account_identifiers(account_id, domain, identifier, identifier_kind, description, created_at, updated_at) SELECT account_id, 'localhost:8080', 'keepone', 'username', 'Keep one wallet', 0, 0 FROM spark_accounts WHERE pubkey = '${pubkey}' ON CONFLICT (domain, identifier) DO NOTHING" >/dev/null

  run unregister_user "deleteone" "localhost:8080"
  [ "$status" -eq 0 ]

  run username_available "deleteone" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.available' 'true'

  run lnurl_discovery "keepone" "localhost:8080"
  [ "$status" -eq 0 ]
  assert_json_nonempty "$output" '.callback'
  metadata_description="$(json_get "$output" '.metadata | fromjson | .[0][1]')"
  [ "$metadata_description" = "Keep one wallet" ]

  run unregister_user "keepone" "localhost:8080"
  [ "$status" -eq 0 ]
}

@test "spark: transfer rejects invalid signature with stable error shape" {
  register_user "badtransfer" "localhost:8080" "Transfer bad signature wallet" >/dev/null

  auth="$(auth_payload "badtransfer")"
  from_pubkey="$(json_get "$auth" '.pubkey')"
  to_pubkey="$(json_get "$auth" '.to_pubkey')"
  to_signature="$(json_get "$auth" '.transfer_to_signature')"

  run transfer_user_status "badtransfer" "localhost:8080" "Bad transfer" "00" "$to_signature" "$from_pubkey" "$to_pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "spark: available rejects invalid username" {
  username="$(printf '%*s' 65 | tr ' ' a)"

  run curl -fsS --header "Host: localhost:8080" "${BASE_URL}/lnurlpay/available/${username}"
  [ "$status" -eq 22 ]
}

@test "spark: register rejects invalid signature" {
  auth="$(auth_payload "badregister")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"

  run register_user_status "badregister" "localhost:8080" "Bad signature" "00" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "spark: strict registration validation rejects modifiers numeric and legacy punctuation" {
  auth="$(auth_payload "validname")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.register_signature')"

  for invalid_username in "alice+btc" "12345" "legacy.name" "bc1alice"; do
    data="{\"username\":\"${invalid_username}\",\"signature\":\"${signature}\",\"timestamp\":${timestamp},\"description\":\"Invalid identifier\"}"
    response="$(http_status_body "POST" "${BASE_URL}/lnurlpay/${pubkey}" "localhost:8080" "$data")"
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"

    [ "$code" = "400" ]
    [ "$body" = '"invalid username"' ]
  done
}

@test "spark: availability rejects phone-like numeric usernames before lookup" {
  response="$(http_status_body "GET" "${BASE_URL}/lnurlpay/available/573005871212" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "400" ]
  [ "$body" = '"invalid username"' ]
}

@test "spark: register rejects stale timestamp" {
  auth="$(auth_payload "staleregister" "1")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.register_signature')"

  run register_user_status "staleregister" "localhost:8080" "Stale timestamp" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "spark: register rejects too-long description" {
  auth="$(auth_payload "longdesc")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.register_signature')"
  description="$(printf '%*s' 256 | tr ' ' a)"

  run register_user_status "longdesc" "localhost:8080" "$description" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "spark: recover returns 404 for missing registration" {
  auth="$(auth_payload "missingrecover")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.recover_signature')"
  docker compose exec -T postgres psql -U user -d lnurl \
    -c "DELETE FROM account_identifiers WHERE account_id IN (SELECT account_id FROM spark_accounts WHERE pubkey = '${pubkey}'); DELETE FROM users WHERE pubkey = '${pubkey}'" >/dev/null

  run recover_user_status "localhost:8080" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "404" ]
}

@test "spark: recover rejects invalid signature" {
  auth="$(auth_payload "badrecover")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"

  run recover_user_status "localhost:8080" "00" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "spark: unregister rejects mismatched signature" {
  register_user "unregisteruser" "localhost:8080" "Unregister test wallet" >/dev/null

  auth="$(auth_payload "unregisteruser")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.unregister_signature')"

  run unregister_user_status "otheruser" "localhost:8080" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}
