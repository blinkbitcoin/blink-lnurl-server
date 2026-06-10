#!/bin/bash

set -eu

VERSION=""
if [[ -f version/version ]];then
  VERSION="$(cat version/version)"
fi

REPO=${REPO:-repo}
BINARY=lnurl-server
OUT=${OUT:-none}
WORKSPACE="$(pwd)"

export CARGO_HOME="$(pwd)/cargo-home"
export CARGO_TARGET_DIR="$(pwd)/cargo-target-dir"

for dir in /usr/include /usr/local/include; do
  if [[ -z "${PROTOC_INCLUDE:-}" && -f "${dir}/google/protobuf/timestamp.proto" ]]; then
    export PROTOC_INCLUDE="${dir}"
  fi
done
export PROTOC_INCLUDE_DIR="${PROTOC_INCLUDE_DIR:-${PROTOC_INCLUDE:-}}"

REAL_PROTOC="$(command -v protoc)"
PROTOC_WRAPPER="$(pwd)/protoc"
cat > "${PROTOC_WRAPPER}" <<EOF
#!/bin/sh
if [ -n "\${PROTOC_INCLUDE:-}" ]; then
  exec "${REAL_PROTOC}" --experimental_allow_proto3_optional -I"\${PROTOC_INCLUDE}" "\$@"
fi
exec "${REAL_PROTOC}" --experimental_allow_proto3_optional "\$@"
EOF
chmod +x "${PROTOC_WRAPPER}"
export PROTOC="${PROTOC_WRAPPER}"

[ -f /workspace/.cargo/config ] && cp /workspace/.cargo/config ${CARGO_HOME}/config

pushd ${REPO}

set -x

cargo build --release --locked --bin ${BINARY} --target ${TARGET}

cd ${CARGO_TARGET_DIR}/${TARGET}/release
OUT_DIR="${BINARY}-${TARGET}-${VERSION}"
rm -rf "${OUT_DIR}" || true
mkdir "${OUT_DIR}"
mv ./${BINARY} ${OUT_DIR}
tar -czvf ${OUT_DIR}.tar.gz ${OUT_DIR}

mv ${OUT_DIR}.tar.gz ${WORKSPACE}/${OUT}/
