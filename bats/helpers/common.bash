#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE_DIR="${ROOT_DIR}/.tmp/e2e"
PID_FILE="${STATE_DIR}/server.pid"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
E2E_AUTH_BIN="${E2E_AUTH_BIN:-${ROOT_DIR}/target/debug/e2e_auth}"

start_stack() {
  RESET_DB=true "${ROOT_DIR}/scripts/start-local-stack.sh"
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

  if [ -n "${amount_msats}" ]; then
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
