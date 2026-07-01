#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  REMOTE_HOST=<host> scripts/remote-amd64-oss-fuzz-replay.sh [project] [run_id]

Required:
  REMOTE_HOST        SSH host or user@host for a native x86_64/amd64 Linux machine.

Optional environment:
  REMOTE_USER        SSH user when REMOTE_HOST has no user prefix. Default: root
  REMOTE_DIR         Remote working directory. Default: /opt/agentic-fuzz-remote
  REFERENCE_ROOT     Local benchmark fixture checkout. Default: /Users/shayaunnejad/vibe-code/localfuzz-winners/reference
  SSH_OPTS           Extra ssh/rsync options.
  REPLAY_TIMEOUT     Container replay timeout seconds. Default: 120
  BUILD_TIMEOUT      OSS-Fuzz build timeout seconds. Default: 1200

This script does not create or destroy cloud VMs. It syncs the local repo plus the
minimum benchmark fixture slices needed for one benchmark project, installs Docker
prerequisites on the remote host, runs the owned OSS-Fuzz build+replay command
on native amd64, and syncs the resulting run artifacts back to runs/remote-amd64.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

project="${1:-localfuzz/c/mongoose}"
project_name="${project##*/}"
run_id="${2:-remote-amd64-${project_name}-$(date -u +%Y%m%d%H%M%S)}"

if [[ -z "${REMOTE_HOST:-}" ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
reference_root="${REFERENCE_ROOT:-/Users/shayaunnejad/vibe-code/localfuzz-winners/reference}"
remote_dir="${REMOTE_DIR:-/opt/agentic-fuzz-remote}"
remote_user="${REMOTE_USER:-root}"
replay_timeout="${REPLAY_TIMEOUT:-120}"
build_timeout="${BUILD_TIMEOUT:-1200}"
ssh_opts=()
if [[ -n "${SSH_OPTS:-}" ]]; then
  # shellcheck disable=SC2206
  ssh_opts=(${SSH_OPTS})
fi

if [[ "${REMOTE_HOST}" == *@* ]]; then
  remote="${REMOTE_HOST}"
else
  remote="${remote_user}@${REMOTE_HOST}"
fi

reference_project="${reference_root}/benchmark/projects/${project_name}"
oss_fuzz="${reference_root}/fixtures/reference/oss-fuzz"
if [[ ! -d "${reference_project}" ]]; then
  echo "missing benchmark project: ${reference_project}" >&2
  exit 3
fi
if [[ ! -d "${oss_fuzz}" ]]; then
  echo "missing OSS-Fuzz root: ${oss_fuzz}" >&2
  exit 3
fi

echo "==> Preparing remote workspace ${remote}:${remote_dir}"
ssh "${ssh_opts[@]}" "${remote}" "mkdir -p '${remote_dir}/repo' '${remote_dir}/reference/benchmark/projects' '${remote_dir}/reference/fixtures/reference'"

echo "==> Syncing repo"
rsync -az --delete \
  --exclude '.git' \
  --exclude '__pycache__' \
  --exclude '.pytest_cache' \
  --exclude 'runs' \
  -e "ssh ${SSH_OPTS:-}" \
  "${repo_root}/" "${remote}:${remote_dir}/repo/"

echo "==> Syncing benchmark project ${project_name}"
rsync -az --delete -e "ssh ${SSH_OPTS:-}" \
  "${reference_project}/" \
  "${remote}:${remote_dir}/reference/benchmark/projects/${project_name}/"

echo "==> Syncing OSS-Fuzz helper tree"
rsync -az --delete \
  --exclude 'build/out' \
  --exclude 'build/work' \
  --exclude 'build/corpus' \
  --exclude '.git' \
  -e "ssh ${SSH_OPTS:-}" \
  "${oss_fuzz}/" \
  "${remote}:${remote_dir}/reference/fixtures/reference/oss-fuzz/"

echo "==> Installing remote prerequisites"
ssh "${ssh_opts[@]}" "${remote}" "set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io python3 rsync ca-certificates
fi
systemctl enable --now docker >/dev/null 2>&1 || service docker start
docker info --format '{{.Architecture}} {{.NCPU}} {{.MemTotal}}'
docker pull ghcr.io/agentic-fuzz/base-builder:v1.2.1
docker pull ghcr.io/agentic-fuzz/base-runner:v1.3.0
"

echo "==> Running owned OSS-Fuzz build+replay (${project}, ${run_id})"
ssh "${ssh_opts[@]}" "${remote}" "set -euo pipefail
cd '${remote_dir}/repo'
AGENTIC_FUZZ_REFERENCE_ROOT='${remote_dir}/reference' \
PYTHONPATH=src \
python3 -m agentic_fuzz_engine.cli \
  --data-root runs/remote-amd64 \
  fidelity-oss-fuzz-build-replay '${project}' \
  --run-id '${run_id}' \
  --summary-only \
  --build-timeout-seconds '${build_timeout}' \
  --replay-timeout-seconds '${replay_timeout}' \
  --repetitions 1
"

echo "==> Syncing run artifacts back"
mkdir -p "${repo_root}/runs/remote-amd64"
rsync -az -e "ssh ${SSH_OPTS:-}" \
  "${remote}:${remote_dir}/repo/runs/remote-amd64/" \
  "${repo_root}/runs/remote-amd64/"

echo "==> Done. Local artifacts: ${repo_root}/runs/remote-amd64/runs/${run_id}"
