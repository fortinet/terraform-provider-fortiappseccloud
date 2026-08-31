#!/usr/bin/env bash

set -euo pipefail

matrix_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
matrix_dev_hostname="https://api.dev1.fortiappsec.com"
matrix_gate="dev_full_waf_matrix_v1"
matrix_mode="${1:-}"

if [[ -n "${matrix_mode}" && "${matrix_mode}" != "--local-only" ]]; then
  echo "usage: $0 [--local-only]" >&2
  exit 2
fi
if [[ -n "${FORTIAPPSECCLOUD_HOSTNAME:-}" && "${FORTIAPPSECCLOUD_HOSTNAME}" != "${matrix_dev_hostname}" ]]; then
  echo "refusing hostname override: this campaign is pinned to dev1" >&2
  exit 2
fi
if [[ "${matrix_mode}" != "--local-only" && -z "${FORTIAPPSECCLOUD_API_TOKEN:-}" ]]; then
  echo "FORTIAPPSECCLOUD_API_TOKEN must already be exported" >&2
  exit 2
fi

matrix_local_env=(
  env
  -u TF_ACC
  -u FORTIAPPSECCLOUD_API_TOKEN
  -u FORTIAPPSECCLOUD_USERNAME
  -u FORTIAPPSECCLOUD_PASSWORD
  -u FORTIAPPSECCLOUD_ACC_DEV_FULL_WAF_WRITE
  -u FORTIAPPSECCLOUD_ACC_PLAN_REVIEWED
  -u FORTIAPPSECCLOUD_ACC_DISPOSABLE_APP
  -u FORTIAPPSECCLOUD_ACC_DISPOSABLE_TEMPLATE
  -u FORTIAPPSECCLOUD_ACC_APP_LIFECYCLE_WRITE
  -u FORTIAPPSECCLOUD_ACC_ALL_RESOURCES_WRITE
  -u FORTIAPPSECCLOUD_ACC_CUSTOM_MODULES_WRITE
  -u FORTIAPPSECCLOUD_ACC_MODULE_DISABLE_WRITE
  -u FORTIAPPSECCLOUD_ACC_TEMPLATE_LIFECYCLE_WRITE
  -u FORTIAPPSECCLOUD_ACC_TEMPLATE_MODULE_WRITE
)

cd "${matrix_root}"

"${matrix_local_env[@]}" go generate ./...
matrix_generation_one="$(git diff --binary | sha256sum | awk '{print $1}')"
"${matrix_local_env[@]}" go generate ./...
matrix_generation_two="$(git diff --binary | sha256sum | awk '{print $1}')"
if [[ "${matrix_generation_one}" != "${matrix_generation_two}" ]]; then
  echo "go generation was not byte-stable" >&2
  exit 1
fi

"${matrix_local_env[@]}" go test ./...
"${matrix_local_env[@]}" go test -race ./internal/...
"${matrix_local_env[@]}" go vet ./...
"${matrix_local_env[@]}" go build ./...
"${matrix_local_env[@]}" terraform fmt -check -recursive examples
git diff --check
TF_CLI_TEST=1 "${matrix_local_env[@]}" go test . -count=1 -v

if [[ "${matrix_mode}" == "--local-only" ]]; then
  echo "local WAF matrix gate passed"
  exit 0
fi

matrix_code_identity="$(git rev-parse --verify HEAD)"
if [[ -n "$(git status --short)" ]]; then
  matrix_code_identity="${matrix_code_identity}-dirty"
fi
matrix_raw_log="$(mktemp)"
chmod 600 "${matrix_raw_log}"
trap 'rm -f "${matrix_raw_log}"' EXIT

set +e
TF_ACC=1 \
FORTIAPPSECCLOUD_HOSTNAME="${matrix_dev_hostname}" \
FORTIAPPSECCLOUD_ACC_DEV_FULL_WAF_WRITE="${matrix_gate}" \
FORTIAPPSECCLOUD_MATRIX_CODE_IDENTITY="${matrix_code_identity}" \
go test ./internal/acceptance \
  -run '^TestAccDevCompleteWAFMatrix$' \
  -count=1 \
  -timeout=180m \
  -v >"${matrix_raw_log}" 2>&1
matrix_live_status=$?
set -e

matrix_summary_path="$(
  sed -n 's/.*dev WAF matrix summary: //p' "${matrix_raw_log}" |
    tail -n 1 |
    sed 's/[[:space:]]*$//'
)"
if [[ -z "${matrix_summary_path}" ]]; then
  echo "live WAF matrix did not produce a sanitized summary" >&2
  exit "${matrix_live_status:-1}"
fi
echo "${matrix_summary_path}"
exit "${matrix_live_status}"
