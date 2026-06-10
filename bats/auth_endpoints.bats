#!/usr/bin/env bats

load "helpers/common.bash"
load "helpers/assertions.bash"

setup_file() {
  start_stack
}

teardown_file() {
  stop_stack
}

@test "auth: register recover and unregister" {
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

@test "auth: availability and duplicate registration preserve Spark contract (D-13/D-17)" {
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

@test "auth: transfer moves Spark username with canonical signatures (D-13/D-15)" {
  run register_user "transferuser" "localhost:8080" "Transfer source wallet"
  [ "$status" -eq 0 ]

  run transfer_user "transferuser" "localhost:8080" "Transfer target wallet"
  [ "$status" -eq 0 ]
  assert_json_equals "$output" '.lightning_address' 'transferuser@localhost:8080'
  assert_json_equals "$output" '.lnurl' 'lnurlp://localhost:8080/lnurlp/transferuser'
}

@test "auth: transfer rejects invalid signature with stable error shape" {
  register_user "badtransfer" "localhost:8080" "Transfer bad signature wallet" >/dev/null

  auth="$(auth_payload "badtransfer")"
  from_pubkey="$(json_get "$auth" '.pubkey')"
  to_pubkey="$(json_get "$auth" '.to_pubkey')"
  to_signature="$(json_get "$auth" '.transfer_to_signature')"

  run transfer_user_status "badtransfer" "localhost:8080" "Bad transfer" "00" "$to_signature" "$from_pubkey" "$to_pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "auth: available rejects invalid username" {
  username="$(printf '%*s' 65 | tr ' ' a)"

  run curl -fsS --header "Host: localhost:8080" "${BASE_URL}/lnurlpay/available/${username}"
  [ "$status" -eq 22 ]
}

@test "auth: register rejects invalid signature" {
  auth="$(auth_payload "badregister")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"

  run register_user_status "badregister" "localhost:8080" "Bad signature" "00" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "auth: register rejects stale timestamp" {
  auth="$(auth_payload "staleregister" "1")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.register_signature')"

  run register_user_status "staleregister" "localhost:8080" "Stale timestamp" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "auth: register rejects too-long description" {
  auth="$(auth_payload "longdesc")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.register_signature')"
  description="$(printf '%*s' 256 | tr ' ' a)"

  run register_user_status "longdesc" "localhost:8080" "$description" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "auth: recover returns 404 for missing registration" {
  unregister_user "missingrecover" "localhost:8080" >/dev/null || true

  auth="$(auth_payload "missingrecover")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.recover_signature')"

  run recover_user_status "localhost:8080" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "404" ]
}

@test "auth: recover rejects invalid signature" {
  auth="$(auth_payload "badrecover")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"

  run recover_user_status "localhost:8080" "00" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}

@test "auth: unregister rejects mismatched signature" {
  register_user "unregisteruser" "localhost:8080" "Unregister test wallet" >/dev/null

  auth="$(auth_payload "unregisteruser")"
  pubkey="$(json_get "$auth" '.pubkey')"
  timestamp="$(json_get "$auth" '.timestamp')"
  signature="$(json_get "$auth" '.unregister_signature')"

  run unregister_user_status "otheruser" "localhost:8080" "$signature" "$timestamp" "$pubkey"
  [ "$status" -eq 0 ]
  [ "$output" = "400" ]
}
