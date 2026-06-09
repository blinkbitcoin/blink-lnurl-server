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
