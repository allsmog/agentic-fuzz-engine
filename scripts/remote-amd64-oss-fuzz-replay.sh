#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  REMOTE_HOST=<host> REMOTE_USER=<user> REMOTE_DIR=<directory> REFERENCE_ROOT=<directory> \
    scripts/remote-amd64-oss-fuzz-replay.sh [project] [run_id]

Required environment:
  REMOTE_HOST       Hostname or IP address only; do not include a user.
  REMOTE_USER       Existing, non-root account on the remote host.
  REMOTE_DIR        Existing directory owned by REMOTE_USER on the remote host.
  REFERENCE_ROOT    Local benchmark fixture checkout.

Optional arguments:
  project           Benchmark project, default: localfuzz/c/mongoose.
  run_id            Safe run identifier. A timestamped identifier is used when omitted.

Optional environment:
  REPLAY_TIMEOUT    Container replay timeout in seconds, default: 120.
  BUILD_TIMEOUT     OSS-Fuzz build timeout in seconds, default: 1200.

The helper only uses the explicit SSH destination. It checks remote prerequisites
and a fresh run directory before copying files. It never creates machines,
installs packages, starts services, pulls images, or removes remote files.
EOF
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || fail "${name} is required"
}

valid_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_env REMOTE_HOST
require_env REMOTE_USER
require_env REMOTE_DIR
require_env REFERENCE_ROOT
[[ -z "${SSH_OPTS:-}" ]] || fail "SSH_OPTS is not supported; configure SSH outside this helper"
: "${REMOTE_HOST:?}"
: "${REMOTE_USER:?}"
: "${REMOTE_DIR:?}"
: "${REFERENCE_ROOT:?}"

project="${1:-localfuzz/c/mongoose}"
project_name="${project##*/}"
run_id="${2:-remote-amd64-${project_name}-$(date -u +%Y%m%d%H%M%S)}"
remote_host="$REMOTE_HOST"
remote_user="$REMOTE_USER"
remote_base="$REMOTE_DIR"
reference_root="$REFERENCE_ROOT"
replay_timeout="${REPLAY_TIMEOUT:-120}"
build_timeout="${BUILD_TIMEOUT:-1200}"

[[ "$remote_host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || fail "REMOTE_HOST must be a hostname or IP address without a user or options"
[[ "$remote_user" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || fail "REMOTE_USER must be a simple account name"
[[ "$remote_user" != "root" ]] || fail "REMOTE_USER must not be root"
[[ "$remote_base" =~ ^/[A-Za-z0-9._/-]+$ ]] || fail "REMOTE_DIR must use only absolute safe path characters"
[[ "$remote_base" != "/" && "$remote_base" != *"//"* && ! "$remote_base" =~ (^|/)\.\.?(/|$) ]] || fail "REMOTE_DIR must not contain root, duplicate slashes, or dot path components"
[[ "$project" =~ ^localfuzz/c/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "project must use the localfuzz/c/<name> form"
[[ "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "run_id contains unsupported characters"
valid_positive_integer "$replay_timeout" || fail "REPLAY_TIMEOUT must be a positive integer"
valid_positive_integer "$build_timeout" || fail "BUILD_TIMEOUT must be a positive integer"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
reference_project="${reference_root}/benchmark/projects/${project_name}"
oss_fuzz="${reference_root}/fixtures/reference/oss-fuzz"
[[ -d "$reference_project" && ! -L "$reference_project" ]] || fail "missing or symlinked benchmark project: ${reference_project}"
[[ -d "$oss_fuzz" && ! -L "$oss_fuzz" ]] || fail "missing or symlinked OSS-Fuzz root: ${oss_fuzz}"

remote="${remote_user}@${remote_host}"
remote_run_dir="${remote_base}/${run_id}"

echo "==> Checking remote prerequisites and creating fresh run directory"
ssh "$remote" bash -s -- "$remote_base" "$run_id" "$remote_user" <<'REMOTE_PREFLIGHT'
set -euo pipefail
remote_base="$1"
run_id="$2"
expected_user="$3"
umask 077

owner_uid() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

[[ "$(id -un)" == "$expected_user" ]]
[[ -d "$remote_base" && ! -L "$remote_base" ]]
[[ "$(owner_uid "$remote_base")" == "$(id -u)" ]]
[[ ! -e "$remote_base/$run_id" && ! -L "$remote_base/$run_id" ]]
command -v docker >/dev/null
command -v python3 >/dev/null
case "$(uname -m)" in x86_64|amd64) ;; *) exit 1 ;; esac
docker info --format '{{.Architecture}}' >/dev/null
docker image inspect ghcr.io/agentic-fuzz/base-builder:v1.2.1 >/dev/null
docker image inspect ghcr.io/agentic-fuzz/base-runner:v1.3.0 >/dev/null

mkdir -m 700 "$remote_base/$run_id"
mkdir -p -m 700 \
  "$remote_base/$run_id/repo" \
  "$remote_base/$run_id/reference/benchmark/projects" \
  "$remote_base/$run_id/reference/fixtures/reference"
[[ -d "$remote_base/$run_id" && ! -L "$remote_base/$run_id" ]]
[[ "$(owner_uid "$remote_base/$run_id")" == "$(id -u)" ]]
[[ -d "$remote_base/$run_id/reference/benchmark/projects" && ! -L "$remote_base/$run_id/reference/benchmark/projects" ]]
[[ -d "$remote_base/$run_id/reference/fixtures/reference" && ! -L "$remote_base/$run_id/reference/fixtures/reference" ]]
REMOTE_PREFLIGHT

echo "==> Copying repository and explicit fixture inputs"
rsync -az \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '.pytest_cache' \
  --exclude 'runs' \
  -e ssh \
  "${repo_root}/" "${remote}:${remote_run_dir}/repo/"
rsync -az -e ssh \
  "${reference_project}/" \
  "${remote}:${remote_run_dir}/reference/benchmark/projects/${project_name}/"
rsync -az \
  --exclude 'build/out' \
  --exclude 'build/work' \
  --exclude 'build/corpus' \
  --exclude '.git' \
  -e ssh \
  "${oss_fuzz}/" \
  "${remote}:${remote_run_dir}/reference/fixtures/reference/oss-fuzz/"

echo "==> Running owned OSS-Fuzz build and replay (${project}, ${run_id})"
ssh "$remote" bash -s -- "$remote_run_dir" "$project" "$run_id" "$build_timeout" "$replay_timeout" <<'REMOTE_RUN'
set -euo pipefail
remote_run_dir="$1"
project="$2"
run_id="$3"
build_timeout="$4"
replay_timeout="$5"

[[ -d "$remote_run_dir/repo" && ! -L "$remote_run_dir/repo" ]]
[[ -d "$remote_run_dir/reference" && ! -L "$remote_run_dir/reference" ]]
cd "$remote_run_dir/repo"
AGENTIC_FUZZ_REFERENCE_ROOT="$remote_run_dir/reference" \
  python3 -m agentic_fuzz_engine.cli \
    --data-root runs/remote-amd64 \
    fidelity-oss-fuzz-build-replay "$project" \
    --run-id "$run_id" \
    --summary-only \
    --build-timeout-seconds "$build_timeout" \
    --replay-timeout-seconds "$replay_timeout" \
    --repetitions 1
REMOTE_RUN

echo "==> Copying run artifacts back to the local checkout"
mkdir -p "${repo_root}/runs/remote-amd64"
rsync -az -e ssh \
  "${remote}:${remote_run_dir}/repo/runs/remote-amd64/" \
  "${repo_root}/runs/remote-amd64/"

echo "==> Done. Local artifacts: ${repo_root}/runs/remote-amd64/runs/${run_id}"
