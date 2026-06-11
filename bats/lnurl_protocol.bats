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

@test "lnurl: btc wallet modifier preserves Spark discovery and callback happy path (D-13/D-15)" {
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

@test "lnurl: usd wallet modifier returns Spark unsupported-wallet LNURL error from discovery or returned callback (D-14/D-15)" {
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

@test "lnurl: unknown and chained wallet modifiers fail before Spark lookup (D-07/D-08/D-12)" {
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

@test "lnurl: phone-like public identifiers do not fall back to numeric legacy usernames (D-01/IDEN-05)" {
  insert_legacy_user "573005871212" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000001" "Numeric legacy wallet"
  insert_legacy_user "12345" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000002" "Invalid phone legacy wallet"

  for phone_like in "573005871212" "12345"; do
    response="$(http_status_body "GET" "${BASE_URL}/.well-known/lnurlp/${phone_like}" "localhost:8080")"
    code="${response##*$'\n'}"
    body="${response%$'\n'*}"

    [ "$code" = "404" ]
    [ "$body" = '""' ]
  done
}

@test "lnurl: legacy non-modifier Spark names still resolve but plus legacy names do not (D-10/D-11/D-12/D-16)" {
  insert_legacy_user "legacy.name" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000003" "Legacy dotted wallet"
  insert_legacy_user "legacy+eur" "localhost:8080" "020000000000000000000000000000000000000000000000000000000000000004" "Legacy plus wallet"
  docker compose exec -T postgres psql -U user -d lnurl \
    -c "INSERT INTO accounts(account_id, provider, created_at, updated_at) VALUES ('spark_legacy_dotted', 'spark', 0, 0) ON CONFLICT (account_id) DO NOTHING; INSERT INTO spark_accounts(account_id, pubkey, created_at, updated_at) VALUES ('spark_legacy_dotted', '020000000000000000000000000000000000000000000000000000000000000003', 0, 0) ON CONFLICT (account_id) DO NOTHING; INSERT INTO account_identifiers(account_id, domain, identifier, identifier_kind, description, created_at, updated_at) VALUES ('spark_legacy_dotted', 'localhost:8080', 'legacy.name', 'username', 'Legacy dotted wallet', 0, 0) ON CONFLICT (domain, identifier) DO NOTHING" >/dev/null

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
