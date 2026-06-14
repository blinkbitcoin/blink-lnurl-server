#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="${ROOT_DIR}/.tmp/e2e"
PID_FILE="${STATE_DIR}/server.pid"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
E2E_AUTH_BIN="${E2E_AUTH_BIN:-${ROOT_DIR}/target/debug/e2e_auth}"
E2E_ZAP_REQUEST_BIN="${E2E_ZAP_REQUEST_BIN:-${ROOT_DIR}/target/debug/e2e_zap_request}"
BLINK_GRAPHQL_MOCK_BIN="${BLINK_GRAPHQL_MOCK_BIN:-${ROOT_DIR}/target/debug/blink_graphql_mock}"
BLINK_GRAPHQL_MOCK_PID_FILE="${STATE_DIR}/blink-graphql-mock.pid"
BLINK_GRAPHQL_MOCK_LOG_FILE="${STATE_DIR}/blink-graphql-mock.log"

start_stack() {
  RESET_DB=true "${ROOT_DIR}/scripts/start-local-stack.sh"
}

start_blink_graphql_mock() {
  mkdir -p "${STATE_DIR}"
  if [ ! -x "${BLINK_GRAPHQL_MOCK_BIN}" ] || [ "${ROOT_DIR}/src/bin/blink_graphql_mock.rs" -nt "${BLINK_GRAPHQL_MOCK_BIN}" ]; then
    cargo build --quiet --locked --bin blink_graphql_mock
  fi
  : >"${BLINK_GRAPHQL_MOCK_LOG_FILE}"
  "${BLINK_GRAPHQL_MOCK_BIN}" 127.0.0.1:0 >"${BLINK_GRAPHQL_MOCK_LOG_FILE}" 2>&1 &
  local pid=$!
  echo "${pid}" >"${BLINK_GRAPHQL_MOCK_PID_FILE}"

  local endpoint=""
  for _ in $(seq 1 30); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    endpoint="$(sed -n '1p' "${BLINK_GRAPHQL_MOCK_LOG_FILE}" 2>/dev/null || true)"
    if [[ "${endpoint}" == http://127.0.0.1:*'/graphql' ]]; then
      export LNURL_BLINK_GRAPHQL_ENDPOINT="${endpoint}"
      return 0
    fi
    sleep 1
  done
  echo "Blink GraphQL mock did not become ready; see ${BLINK_GRAPHQL_MOCK_LOG_FILE}" >&2
  stop_blink_graphql_mock
  return 1
}

stop_blink_graphql_mock() {
  if [ -f "${BLINK_GRAPHQL_MOCK_PID_FILE}" ]; then
    local pid
    pid="$(<"${BLINK_GRAPHQL_MOCK_PID_FILE}")"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      for _ in $(seq 1 10); do
        if ! kill -0 "${pid}" 2>/dev/null; then
          break
        fi
        sleep 1
      done
      if kill -0 "${pid}" 2>/dev/null; then
        kill -9 "${pid}" 2>/dev/null || true
      fi
    fi
    rm -f "${BLINK_GRAPHQL_MOCK_PID_FILE}"
  fi
}

stop_stack() {
  if [ -f "${PID_FILE}" ]; then
    local pid
    pid="$(<"${PID_FILE}")"
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      for _ in $(seq 1 10); do
        if ! kill -0 "${pid}" 2>/dev/null; then
          break
        fi
        sleep 1
      done
      if kill -0 "${pid}" 2>/dev/null; then
        kill -9 "${pid}" 2>/dev/null || true
      fi
    fi
    rm -f "${PID_FILE}"
  fi
}

auth_payload() {
  local username="${1:?username is required}"
  local timestamp="${2:-}"
  if [ -x "${E2E_AUTH_BIN}" ] && [ "${E2E_AUTH_BIN}" -nt "${ROOT_DIR}/src/bin/e2e_auth.rs" ]; then
    if [ -n "${timestamp}" ]; then
      "${E2E_AUTH_BIN}" "${username}" "${timestamp}"
    else
      "${E2E_AUTH_BIN}" "${username}"
    fi
  else
    if [ -n "${timestamp}" ]; then
      cargo run --quiet --locked --bin e2e_auth -- "${username}" "${timestamp}"
    else
      cargo run --quiet --locked --bin e2e_auth -- "${username}"
    fi
  fi
}

auth_pubkey() {
  local username="${1:?username is required}"
  local auth
  auth="$(auth_payload "${username}")"
  json_get "${auth}" '.pubkey'
}

zap_request_for_discovery() {
  local discovery_json="${1:?discovery JSON is required}"
  local amount_msats="${2:?amount msats is required}"
  local nostr_pubkey
  nostr_pubkey="$(json_get "${discovery_json}" '.nostrPubkey')"

  if [ -x "${E2E_ZAP_REQUEST_BIN}" ] && [ "${E2E_ZAP_REQUEST_BIN}" -nt "${ROOT_DIR}/src/bin/e2e_zap_request.rs" ]; then
    "${E2E_ZAP_REQUEST_BIN}" "${nostr_pubkey}" "${amount_msats}"
  else
    cargo run --quiet --locked --bin e2e_zap_request -- "${nostr_pubkey}" "${amount_msats}"
  fi
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

create_blink_account() {
  local identifier="${1:?identifier is required}"
  local description="${2:-Blink test wallet}"
  local default_wallet="${3:-btc}"
  local btc_wallet_id="${4:-btc-wallet-${identifier//[^[:alnum:]]/-}}"
  local usd_wallet_id="${5:-usd-wallet-${identifier//[^[:alnum:]]/-}}"
  local token
  token="$(internal_test_token "blink:accounts:create")"

  curl -fsS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${token}" \
    --data "$(jq -cn --arg domain "localhost:8080" --arg blink_account_id "acct-${identifier//[^[:alnum:]]/-}" --arg btc_wallet_id "${btc_wallet_id}" --arg usd_wallet_id "${usd_wallet_id}" --arg default_wallet "${default_wallet}" --arg description "${description}" --arg identifier "${identifier}" '{domain:$domain,blink_account_id:$blink_account_id,btc_wallet_id:$btc_wallet_id,usd_wallet_id:$usd_wallet_id,default_wallet:$default_wallet,description:$description,identifiers:[$identifier]}')" \
    "${BASE_URL}/internal/blink/accounts" | jq -cer '.'
}

create_blink_account_body() {
  local blink_account_id="${1:?blink account id is required}"
  local btc_wallet_id="${2:?BTC wallet id is required}"
  local usd_wallet_id="${3:?USD wallet id is required}"
  local default_wallet="${4:?default wallet is required}"
  local description="${5:?description is required}"
  shift 5
  local identifiers
  identifiers="$(printf '%s\n' "$@" | jq -R . | jq -s .)"

  jq -cn \
    --arg domain "localhost:8080" \
    --arg blink_account_id "${blink_account_id}" \
    --arg btc_wallet_id "${btc_wallet_id}" \
    --arg usd_wallet_id "${usd_wallet_id}" \
    --arg default_wallet "${default_wallet}" \
    --arg description "${description}" \
    --argjson identifiers "${identifiers}" \
    '{domain:$domain,blink_account_id:$blink_account_id,btc_wallet_id:$btc_wallet_id,usd_wallet_id:$usd_wallet_id,default_wallet:$default_wallet,description:$description,identifiers:$identifiers}'
}

create_blink_account_multi() {
  local blink_account_id="${1:?blink account id is required}"
  local description="${2:?description is required}"
  local default_wallet="${3:?default wallet is required}"
  local btc_wallet_id="${4:?BTC wallet id is required}"
  local usd_wallet_id="${5:?USD wallet id is required}"
  shift 5
  local token
  local body
  token="$(internal_test_token "blink:accounts:create")"
  body="$(create_blink_account_body "${blink_account_id}" "${btc_wallet_id}" "${usd_wallet_id}" "${default_wallet}" "${description}" "$@")"

  curl -fsS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${token}" \
    --data "${body}" \
    "${BASE_URL}/internal/blink/accounts" | jq -cer '.'
}

post_internal_blink_account_status_body() {
  local body="${1:?body is required}"
  local token="${2:-}"
  local headers=(
    --header "Host: localhost:8080"
    --header "Content-Type: application/json"
  )
  if [ -n "${token}" ]; then
    headers+=(--header "Authorization: Bearer ${token}")
  fi

  curl -sS \
    --request POST \
    "${headers[@]}" \
    --data "${body}" \
    --write-out $'\n%{http_code}' \
    "${BASE_URL}/internal/blink/accounts"
}

create_blink_account_status() {
  local identifier="${1:?identifier is required}"
  local description="${2:-Blink test wallet}"
  local default_wallet="${3:-btc}"
  local token
  token="$(internal_test_token "blink:accounts:create")"

  curl -sS -o /dev/null -w "%{http_code}" \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${token}" \
    --data "$(jq -cn --arg domain "localhost:8080" --arg blink_account_id "acct-dupe-${identifier//[^[:alnum:]]/-}" --arg btc_wallet_id "btc-wallet-dupe-${identifier//[^[:alnum:]]/-}" --arg usd_wallet_id "usd-wallet-dupe-${identifier//[^[:alnum:]]/-}" --arg default_wallet "${default_wallet}" --arg description "${description}" --arg identifier "${identifier}" '{domain:$domain,blink_account_id:$blink_account_id,btc_wallet_id:$btc_wallet_id,usd_wallet_id:$usd_wallet_id,default_wallet:$default_wallet,description:$description,identifiers:[$identifier]}')" \
    "${BASE_URL}/internal/blink/accounts"
}

blink_lnurl_discovery() {
  local local_part="${1:?local part is required}"
  lnurl_discovery "${local_part}" "localhost:8080"
}

blink_lnurl_callback() {
  lnurl_callback "$@"
}

blink_settlement_notify() {
  local payment_hash="${1:?payment hash is required}"
  local preimage="${2:?preimage is required}"
  local payment_request="${3:-}"

  curl -fsS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --data "$(jq -cn --arg payment_hash "${payment_hash}" --arg preimage "${preimage}" --arg payment_request "${payment_request}" '{paymentHash:$payment_hash,paymentPreimage:$preimage,status:"PAID"} + (if $payment_request == "" then {} else {paymentRequest:$payment_request} end)')" \
    "${BASE_URL}/webhook/blink"
}

internal_identifier_lookup() {
  local identifier="${1:?identifier is required}"
  local token
  token="$(internal_test_token "accounts:read")"

  curl -fsS \
    --header "Host: localhost:8080" \
    --header "Authorization: Bearer ${token}" \
    "${BASE_URL}/internal/domains/localhost:8080/identifiers/${identifier}" | jq -cer '.'
}

internal_identifier_lookup_status_body() {
  local identifier="${1:?identifier is required}"
  local token="${2:-}"
  local headers=(--header "Host: localhost:8080")
  if [ -n "${token}" ]; then
    headers+=(--header "Authorization: Bearer ${token}")
  fi

  curl -sS \
    --request GET \
    "${headers[@]}" \
    --write-out $'\n%{http_code}' \
    "${BASE_URL}/internal/domains/localhost:8080/identifiers/${identifier}"
}

blink_settlement_notify_without_preimage() {
  local payment_hash="${1:?payment hash is required}"
  local payment_request="${2:-}"

  curl -fsS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --data "$(jq -cn --arg payment_hash "${payment_hash}" --arg payment_request "${payment_request}" '{paymentHash:$payment_hash,status:"PAID"} + (if $payment_request == "" then {} else {paymentRequest:$payment_request} end)')" \
    "${BASE_URL}/webhook/blink"
}

blink_expired_notify() {
  local payment_hash="${1:?payment hash is required}"
  local payment_request="${2:-}"

  curl -fsS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --data "$(jq -cn --arg payment_hash "${payment_hash}" --arg payment_request "${payment_request}" '{paymentHash:$payment_hash,status:"EXPIRED"} + (if $payment_request == "" then {} else {paymentRequest:$payment_request} end)')" \
    "${BASE_URL}/webhook/blink"
}

blink_settlement_notify_status_body() {
  local body="${1:?body is required}"
  local headers=(
    --header "Host: localhost:8080"
    --header "Content-Type: application/json"
  )

  curl -sS \
    --request POST \
    "${headers[@]}" \
    --data "${body}" \
    --write-out $'\n%{http_code}' \
    "${BASE_URL}/webhook/blink"
}

transfer_blink_identifier_to_spark() {
  local identifier="${1:?identifier is required}"
  local destination_pubkey="${2:?destination pubkey is required}"
  local description="${3:?description is required}"
  local token
  token="$(internal_test_token "transfer:write")"

  curl -fsS \
    --request POST \
    --header "Host: localhost:8080" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer ${token}" \
    --data "$(jq -cn --arg domain "localhost:8080" --arg identifier "${identifier}" --arg destination_spark_pubkey "${destination_pubkey}" --arg description "${description}" '{domain:$domain,identifier:$identifier,destination_spark_pubkey:$destination_spark_pubkey,description:$description}')" \
    "${BASE_URL}/internal/identifiers/transfer-to-spark" | jq -cer '.'
}

identifier_owner_provider() {
  local identifier="${1:?identifier is required}"
  local sql_identifier
  sql_identifier="$(sql_literal_escape "${identifier}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT a.provider FROM account_identifiers ai JOIN accounts a ON a.account_id = ai.account_id WHERE ai.domain = 'localhost:8080' AND ai.identifier = '${sql_identifier}'"
}

account_identifier_exists() {
  local identifier="${1:?identifier is required}"
  local sql_identifier
  sql_identifier="$(sql_literal_escape "${identifier}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT CASE WHEN EXISTS (SELECT 1 FROM account_identifiers WHERE domain = 'localhost:8080' AND identifier = '${sql_identifier}') THEN 'true' ELSE 'false' END"
}

invoice_account_provider() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT provider FROM invoices WHERE payment_hash = '${sql_payment_hash}'"
}

invoice_wallet_kind() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT wallet_kind FROM invoices WHERE payment_hash = '${sql_payment_hash}'"
}

invoice_has_preimage() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT CASE WHEN preimage IS NULL THEN 'false' ELSE 'true' END FROM invoices WHERE payment_hash = '${sql_payment_hash}'"
}

configure_domain_webhook() {
  local domain="${1:?domain is required}"
  local url="${2:?url is required}"
  local secret="${3:?secret is required}"
  local sql_domain
  local sql_url
  local sql_secret
  sql_domain="$(sql_literal_escape "${domain}")"
  sql_url="$(sql_literal_escape "${url}")"
  sql_secret="$(sql_literal_escape "${secret}")"
  docker compose exec -T postgres psql -U user -d lnurl \
    -c "INSERT INTO domain_webhooks(domain, url, webhook_secret) VALUES ('${sql_domain}', '${sql_url}', '${sql_secret}') ON CONFLICT (domain) DO UPDATE SET url = EXCLUDED.url, webhook_secret = EXCLUDED.webhook_secret" >/dev/null
}

webhook_delivery_count() {
  webhook_delivery_count_for_payment_hash "$@"
}

zap_side_effect_state() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT CONCAT(COUNT(*), ':', COALESCE(MAX(CASE WHEN zap_request IS NULL THEN 'missing' ELSE 'present' END), 'missing')) FROM zaps WHERE payment_hash = '${sql_payment_hash}'"
}

pending_zap_receipt_count() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT COUNT(*) FROM pending_zap_receipts WHERE payment_hash = '${sql_payment_hash}'"
}

zap_receipt_side_effect_state() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT CASE WHEN EXISTS (SELECT 1 FROM pending_zap_receipts WHERE payment_hash = '${sql_payment_hash}') OR EXISTS (SELECT 1 FROM zaps WHERE payment_hash = '${sql_payment_hash}' AND zap_event IS NOT NULL) THEN 'present' ELSE 'missing' END"
}

webhook_delivery_count_for_payment_hash() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT COUNT(*) FROM webhook_deliveries WHERE identifier = '${sql_payment_hash}' OR payload::text LIKE '%${sql_payment_hash}%'"
}

webhook_delivery_payload_for_payment_hash() {
  local payment_hash="${1:?payment hash is required}"
  local sql_payment_hash
  sql_payment_hash="$(sql_literal_escape "${payment_hash}")"
  docker compose exec -T postgres psql -U user -d lnurl -tA \
    -c "SELECT payload FROM webhook_deliveries WHERE identifier = '${sql_payment_hash}' OR payload::text LIKE '%${sql_payment_hash}%' ORDER BY id DESC LIMIT 1"
}

register_user() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local description="${3:-Test LNURL user}"
  local auth
  local pubkey
  local timestamp
  local signature

  auth="$(auth_payload "${username}")"
  pubkey="$(json_get "${auth}" '.pubkey')"
  timestamp="$(json_get "${auth}" '.timestamp')"
  signature="$(json_get "${auth}" '.register_signature')"

  curl -fsS \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${username}\",\"signature\":\"${signature}\",\"timestamp\":${timestamp},\"description\":\"${description}\"}" \
    "${BASE_URL}/lnurlpay/${pubkey}" | jq -cer '.'
}

register_user_status() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local description="${3:?description is required}"
  local signature="${4:?signature is required}"
  local timestamp="${5:?timestamp is required}"
  local pubkey="${6:?pubkey is required}"

  curl -sS -o /dev/null -w "%{http_code}" \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${username}\",\"signature\":\"${signature}\",\"timestamp\":${timestamp},\"description\":\"${description}\"}" \
    "${BASE_URL}/lnurlpay/${pubkey}"
}

recover_user() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local auth
  local pubkey
  local timestamp
  local signature

  auth="$(auth_payload "${username}")"
  pubkey="$(json_get "${auth}" '.pubkey')"
  timestamp="$(json_get "${auth}" '.timestamp')"
  signature="$(json_get "${auth}" '.recover_signature')"

  curl -fsS \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"signature\":\"${signature}\",\"timestamp\":${timestamp}}" \
    "${BASE_URL}/lnurlpay/${pubkey}/recover" | jq -cer '.'
}

recover_user_status() {
  local host="${1:?host is required}"
  local signature="${2:?signature is required}"
  local timestamp="${3:?timestamp is required}"
  local pubkey="${4:?pubkey is required}"

  curl -sS -o /dev/null -w "%{http_code}" \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"signature\":\"${signature}\",\"timestamp\":${timestamp}}" \
    "${BASE_URL}/lnurlpay/${pubkey}/recover"
}

unregister_user() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local auth
  local pubkey
  local timestamp
  local signature

  auth="$(auth_payload "${username}")"
  pubkey="$(json_get "${auth}" '.pubkey')"
  timestamp="$(json_get "${auth}" '.timestamp')"
  signature="$(json_get "${auth}" '.unregister_signature')"

  curl -fsS \
    --request DELETE \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${username}\",\"signature\":\"${signature}\",\"timestamp\":${timestamp}}" \
    "${BASE_URL}/lnurlpay/${pubkey}"
}

unregister_user_status() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local signature="${3:?signature is required}"
  local timestamp="${4:?timestamp is required}"
  local pubkey="${5:?pubkey is required}"

  curl -sS -o /dev/null -w "%{http_code}" \
    --request DELETE \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${username}\",\"signature\":\"${signature}\",\"timestamp\":${timestamp}}" \
    "${BASE_URL}/lnurlpay/${pubkey}"
}

transfer_user() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local description="${3:-Transferred LNURL user}"
  local auth
  local from_pubkey
  local to_pubkey
  local from_signature
  local to_signature

  auth="$(auth_payload "${username}")"
  from_pubkey="$(json_get "${auth}" '.pubkey')"
  to_pubkey="$(json_get "${auth}" '.to_pubkey')"
  from_signature="$(json_get "${auth}" '.transfer_from_signature')"
  to_signature="$(json_get "${auth}" '.transfer_to_signature')"

  curl -fsS \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${username}\",\"description\":\"${description}\",\"from_pubkey\":\"${from_pubkey}\",\"from_signature\":\"${from_signature}\",\"to_signature\":\"${to_signature}\"}" \
    "${BASE_URL}/lnurlpay/${to_pubkey}/transfer" | jq -cer '.'
}

transfer_user_status() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local description="${3:?description is required}"
  local from_signature="${4:?from signature is required}"
  local to_signature="${5:?to signature is required}"
  local from_pubkey="${6:?from pubkey is required}"
  local to_pubkey="${7:?to pubkey is required}"

  curl -sS -o /dev/null -w "%{http_code}" \
    --header "Host: ${host}" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${username}\",\"description\":\"${description}\",\"from_pubkey\":\"${from_pubkey}\",\"from_signature\":\"${from_signature}\",\"to_signature\":\"${to_signature}\"}" \
    "${BASE_URL}/lnurlpay/${to_pubkey}/transfer"
}

http_status_body() {
  local method="${1:?method is required}"
  local url="${2:?url is required}"
  local host="${3:?host is required}"
  local data="${4:-}"

  if [ -n "${data}" ]; then
    curl -sS \
      --request "${method}" \
      --header "Host: ${host}" \
      --header "Content-Type: application/json" \
      --data "${data}" \
      --write-out $'\n%{http_code}' \
      "${url}"
  else
    curl -sS \
      --request "${method}" \
      --header "Host: ${host}" \
      --write-out $'\n%{http_code}' \
      "${url}"
  fi
}

insert_legacy_user() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  local pubkey="${3:?pubkey is required}"
  local description="${4:-Legacy Spark wallet}"
  local sql_username="${username//\'/\'\'}"
  local sql_host="${host//\'/\'\'}"
  local sql_pubkey="${pubkey//\'/\'\'}"
  local sql_description="${description//\'/\'\'}"

  docker compose exec -T postgres psql -U user -d lnurl \
    -c "INSERT INTO users(domain, pubkey, name, description, updated_at) VALUES ('${sql_host}', '${sql_pubkey}', '${sql_username}', '${sql_description}', 0) ON CONFLICT (domain, pubkey) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = EXCLUDED.updated_at" >/dev/null
}

username_available() {
  local username="${1:?username is required}"
  local host="${2:?host is required}"
  curl -fsS --header "Host: ${host}" "${BASE_URL}/lnurlpay/available/${username}" | jq -cer '.'
}

lnurl_discovery() {
  local local_part="${1:?local part is required}"
  local host="${2:?host is required}"
  curl -fsS --header "Host: ${host}" "${BASE_URL}/.well-known/lnurlp/${local_part}" | jq -cer '.'
}

lnurl_callback() {
  local callback_url="${1:?callback URL is required}"
  local amount_msats="${2:-}"
  local nostr="${3:-}"

  if [ -n "${amount_msats}" ] && [ -n "${nostr}" ]; then
    curl -fsS --get --data-urlencode "amount=${amount_msats}" --data-urlencode "nostr=${nostr}" "${callback_url}" | jq -cer '.'
  elif [ -n "${amount_msats}" ]; then
    curl -fsS --get --data-urlencode "amount=${amount_msats}" "${callback_url}" | jq -cer '.'
  else
    curl -fsS "${callback_url}" | jq -cer '.'
  fi
}

json_get() {
  local json="${1:?json is required}"
  local jq_path="${2:?jq path is required}"
  jq -cer "${jq_path}" <<<"${json}"
}

sql_literal_escape() {
  local value="${1:?SQL literal value is required}"
  printf "%s" "${value//\'/\'\'}"
}
