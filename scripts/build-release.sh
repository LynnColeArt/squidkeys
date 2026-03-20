#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$(sed -n 's/^const Version = "\(.*\)"$/\1/p' "${ROOT_DIR}/version.go")}"
OUTPUT_DIR="${SQUIDKEYS_RELEASE_DIR:-${ROOT_DIR}/dist}"
DEFAULT_TARGET="$(go env GOOS)/$(go env GOARCH)"
TARGETS="${SQUIDKEYS_RELEASE_TARGETS:-${DEFAULT_TARGET}}"
CHECKSUMS_FILE="${OUTPUT_DIR}/squidkeys-go_${VERSION}_checksums.txt"

if [[ -z "${VERSION}" ]]; then
  echo "could not determine version from version.go" >&2
  exit 1
fi

checksum_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file}"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}"
    return
  fi
  echo "need sha256sum or shasum to generate release checksums" >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"
: > "${CHECKSUMS_FILE}"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

for target in ${TARGETS}; do
  IFS=/ read -r goos goarch <<< "${target}"
  if [[ -z "${goos}" || -z "${goarch}" ]]; then
    echo "invalid target ${target}; expected GOOS/GOARCH" >&2
    exit 1
  fi

  artifact_base="squidkeys-go_${VERSION}_${goos}_${goarch}"
  staging_dir="${TMP_DIR}/${artifact_base}"
  rm -rf "${staging_dir}"
  mkdir -p "${staging_dir}"

  exe_suffix=""
  if [[ "${goos}" == "windows" ]]; then
    exe_suffix=".exe"
  fi

  echo "building ${artifact_base}"
  (
    cd "${ROOT_DIR}"
    GOOS="${goos}" GOARCH="${goarch}" \
      go build -trimpath -o "${staging_dir}/squidkeys-api${exe_suffix}" ./cmd/squidkeys-api
    GOOS="${goos}" GOARCH="${goarch}" \
      go build -trimpath -o "${staging_dir}/squidkeys-mcp${exe_suffix}" ./cmd/squidkeys-mcp
  )

  cp "${ROOT_DIR}/README.md" "${staging_dir}/"
  cp "${ROOT_DIR}/API_SPEC.md" "${staging_dir}/"

  archive_path="${OUTPUT_DIR}/${artifact_base}.tar.gz"
  tar -C "${TMP_DIR}" -czf "${archive_path}" "${artifact_base}"
  checksum_file "${archive_path}" >> "${CHECKSUMS_FILE}"
done

echo "release artifacts written to ${OUTPUT_DIR}"
echo "checksums written to ${CHECKSUMS_FILE}"
