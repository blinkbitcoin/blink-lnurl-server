#!/usr/bin/env bash

assert_json_equals() {
  local json="${1:?json is required}"
  local jq_path="${2:?jq path is required}"
  local expected="${3:?expected value is required}"
  local actual

  if ! actual="$(jq -cr "${jq_path}" <<<"${json}")"; then
    echo "assert_json_equals failed: ${jq_path} was not found" >&2
    return 1
  fi

  if [ "${actual}" != "${expected}" ]; then
    echo "assert_json_equals failed: ${jq_path} expected '${expected}' got '${actual}'" >&2
    return 1
  fi
}

assert_json_nonempty() {
  local json="${1:?json is required}"
  local jq_path="${2:?jq path is required}"
  local actual

  if ! actual="$(jq -cer "${jq_path}" <<<"${json}")"; then
    echo "assert_json_nonempty failed: ${jq_path} was not found" >&2
    return 1
  fi

  if [ -z "${actual}" ] || [ "${actual}" = "null" ]; then
    echo "assert_json_nonempty failed: ${jq_path} was empty" >&2
    return 1
  fi
}

assert_json_absent_or_not_contains() {
  local json="${1:?json is required}"
  local jq_path="${2:?jq path is required}"
  local needle="${3:?needle is required}"
  local actual

  actual="$(jq -cer "${jq_path} // empty" <<<"${json}" 2>/dev/null || true)"
  if [ -n "${actual}" ] && [[ "${actual}" == *"${needle}"* ]]; then
    echo "assert_json_absent_or_not_contains failed: ${jq_path} contained '${needle}'" >&2
    return 1
  fi
}
