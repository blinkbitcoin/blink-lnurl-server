#!/usr/bin/env bats

load "helpers/common.bash"
load "helpers/assertions.bash"

setup_file() {
  start_stack
}

teardown_file() {
  stop_stack
}

setup() {
  register_user "alice" "localhost:8080" "Alice test wallet" >/dev/null
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

@test "lnurl: unknown user returns 404" {
  response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/missing" "localhost:8080")"
  code="${response##*$'\n'}"
  body="${response%$'\n'*}"

  [ "$code" = "404" ]
  [ "$body" = '""' ]
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
