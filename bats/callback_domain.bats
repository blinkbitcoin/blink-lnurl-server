#!/usr/bin/env bats

load "helpers/common.bash"
load "helpers/assertions.bash"

setup_file() {
  export LNURL_INTERNAL_JWKS_PATH="${ROOT_DIR}/tests/fixtures/internal_auth_jwks.json"
  export LNURL_INTERNAL_JWT_ISSUER="https://issuer.internal.test"
  export LNURL_INTERNAL_JWT_AUDIENCE="lnurl-server.internal.test"
  export LNURL_CALLBACK_DOMAIN="127.0.0.1:8080"
  export LNURL_WEBHOOK_DOMAIN="localhost:8080"
  start_stack
}

teardown_file() {
  stop_stack
}

setup() {
  register_user "alice" "localhost:8080" "Alice callback-domain wallet" >/dev/null
}

@test "lnurl: configured callback domain uses path domain for invoice generation" {
  run lnurl_discovery "alice" "localhost:8080"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.callback' 'http://127.0.0.1:8080/lnurlp/localhost:8080/alice/invoice'

  callback_url="$(json_get "$output" '.callback')"
  run lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]

  assert_json_nonempty "$output" '.pr'
  assert_json_equals "$output" '.verify | startswith("http://127.0.0.1:8080/verify/")' 'true'
  assert_json_equals "$output" '.routes | length' '0'
  assert_json_absent_or_not_contains "$output" '.status' 'ERROR'

  verify_url="$(json_get "$output" '.verify')"
  run curl -fsS "$verify_url"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.status' 'OK'
  assert_json_equals "$output" '.settled' 'false'
  assert_json_nonempty "$output" '.pr'
}

@test "lnurl: configured callback domain preserves wallet modifier in callback path" {
  run lnurl_discovery "alice+btc" "localhost:8080"
  [ "$status" -eq 0 ]

  assert_json_equals "$output" '.callback' 'http://127.0.0.1:8080/lnurlp/localhost:8080/alice+btc/invoice'

  callback_url="$(json_get "$output" '.callback')"
  run lnurl_callback "$callback_url" "1000"
  [ "$status" -eq 0 ]

  assert_json_nonempty "$output" '.pr'
  assert_json_equals "$output" '.verify | startswith("http://127.0.0.1:8080/verify/")' 'true'
}
