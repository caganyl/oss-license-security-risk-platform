#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Sandbox Scanner — Entrypoint
#
# Reads scan parameters from environment variables, clones the target
# repository (or extracts an uploaded archive), runs the appropriate
# dependency parsers, and prints a single JSON object to stdout.
#
# Required env vars:
#   SCAN_ID          — UUID of the scan record
#   REPO_URL         — HTTPS or SSH clone URL
#   REPO_REF         — branch name, tag, or full commit SHA
#   ECOSYSTEMS       — comma-separated list: nodejs,python
#
# Optional env vars:
#   ACCESS_TOKEN     — credential injected by the worker; never logged
#   UPLOAD_ARCHIVE   — path to a tar.gz file (skips git clone)
#   SHALLOW_DEPTH    — git clone depth (default: 1)
#   MAX_REPO_MB      — abort clone if repo exceeds this size in MiB (default: 512)
#
# Exits 0 on success; non-zero on failure.  Result JSON is always the last
# line printed to stdout so the calling worker can parse it with tail -1.
# ---------------------------------------------------------------------------

set -euo pipefail

# ---------------------------------------------------------------------------
# Cleanup — always runs on exit (success or failure)
# ---------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    # Securely wipe workspace contents; ignore errors if already gone
    if [[ -d /workspace ]]; then
        find /workspace -mindepth 1 -delete 2>/dev/null || true
    fi
    # Scrub credential from git config in case it leaked
    git config --global --unset-all url."https://${ACCESS_TOKEN:-}@".insteadOf 2>/dev/null || true
    exit "$exit_code"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Logging (stderr so it doesn't pollute the stdout JSON result)
# ---------------------------------------------------------------------------
log()  { echo "[$(date -u +%H:%M:%SZ)] $*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
[[ -n "${SCAN_ID:-}"    ]] || fail "SCAN_ID is required"
[[ -n "${REPO_URL:-}"   ]] || fail "REPO_URL is required"
[[ -n "${REPO_REF:-}"   ]] || fail "REPO_REF is required"
[[ -n "${ECOSYSTEMS:-}" ]] || fail "ECOSYSTEMS is required"

SHALLOW_DEPTH="${SHALLOW_DEPTH:-1}"
MAX_REPO_MB="${MAX_REPO_MB:-512}"
WORK_DIR="/workspace/${SCAN_ID}"

mkdir -p "${WORK_DIR}"

# ---------------------------------------------------------------------------
# Source acquisition: git clone or archive extraction
# ---------------------------------------------------------------------------
if [[ -n "${UPLOAD_ARCHIVE:-}" ]]; then
    log "Extracting uploaded archive: ${UPLOAD_ARCHIVE}"
    [[ -f "${UPLOAD_ARCHIVE}" ]] || fail "Archive not found: ${UPLOAD_ARCHIVE}"
    tar -xzf "${UPLOAD_ARCHIVE}" -C "${WORK_DIR}" --strip-components=1
else
    log "Cloning ${REPO_URL} at ref ${REPO_REF} (depth ${SHALLOW_DEPTH})"

    # Inject token via git credential helper URL rewrite (never touches disk)
    if [[ -n "${ACCESS_TOKEN:-}" ]]; then
        AUTHED_URL="${REPO_URL/https:\/\//https:\/\/${ACCESS_TOKEN}@}"
    else
        AUTHED_URL="${REPO_URL}"
    fi

    # Check repo size via git ls-remote before a full clone when possible
    # (network call; skip on SSH URLs)
    if [[ "${REPO_URL}" == https://* ]]; then
        PACK_SIZE=$(git ls-remote --refs "${AUTHED_URL}" 2>/dev/null | wc -c || echo 0)
        # Rough heuristic: if ls-remote response > 1 MiB the metadata alone is huge
        if (( PACK_SIZE > 1048576 )); then
            log "WARN: repository metadata is unusually large (${PACK_SIZE} bytes)"
        fi
    fi

    git clone \
        --depth "${SHALLOW_DEPTH}" \
        --single-branch \
        --branch "${REPO_REF}" \
        --no-tags \
        --filter=blob:limit="${MAX_REPO_MB}m" \
        "${AUTHED_URL}" \
        "${WORK_DIR}" \
    || fail "git clone failed"

    # Unset credential immediately after clone
    unset ACCESS_TOKEN AUTHED_URL
fi

log "Source ready at ${WORK_DIR}"

# ---------------------------------------------------------------------------
# Manifest discovery helpers
# ---------------------------------------------------------------------------

find_manifests() {
    local dir="$1" pattern="$2"
    # Exclude hidden dirs and common non-source paths
    find "${dir}" \
        -not \( -name '.git' -prune \) \
        -not \( -name 'node_modules' -prune \) \
        -not \( -name '.venv' -prune \) \
        -not \( -name '__pycache__' -prune \) \
        -name "${pattern}" \
        -type f
}

# ---------------------------------------------------------------------------
# Result accumulator (JSON array of dependency objects)
# ---------------------------------------------------------------------------
DEPS_JSON="[]"
SCAN_FILES_JSON="[]"
PARSE_ERRORS_JSON="[]"

append_deps() {
    local new_deps="$1"
    DEPS_JSON=$(jq -n --argjson a "${DEPS_JSON}" --argjson b "${new_deps}" '$a + $b')
}

append_scan_file() {
    local ecosystem="$1" filename="$2" filepath="$3"
    local hash
    hash=$(sha256sum "${filepath}" | awk '{print $1}')
    local size
    size=$(stat -c%s "${filepath}")
    local rel_path="${filepath#${WORK_DIR}/}"
    local entry
    entry=$(jq -n \
        --arg eco   "${ecosystem}" \
        --arg fn    "${filename}" \
        --arg fp    "${rel_path}" \
        --arg hash  "${hash}" \
        --argjson sz "${size}" \
        '{ecosystem:$eco, filename:$fn, file_path:$fp, file_hash:$hash, size_bytes:$sz}')
    SCAN_FILES_JSON=$(jq -n --argjson a "${SCAN_FILES_JSON}" --argjson e "${entry}" '$a + [$e]')
}

record_error() {
    local ecosystem="$1" file="$2" msg="$3"
    local entry
    entry=$(jq -n --arg eco "${ecosystem}" --arg file "${file}" --arg msg "${msg}" \
        '{ecosystem:$eco, file:$file, error:$msg}')
    PARSE_ERRORS_JSON=$(jq -n --argjson a "${PARSE_ERRORS_JSON}" --argjson e "${entry}" '$a + [$e]')
    log "PARSE ERROR [${ecosystem}] ${file}: ${msg}"
}

# ---------------------------------------------------------------------------
# Node.js parser
# ---------------------------------------------------------------------------
parse_nodejs() {
    log "Scanning Node.js manifests…"

    while IFS= read -r manifest; do
        local manifest_dir
        manifest_dir=$(dirname "${manifest}")
        local rel_path="${manifest#${WORK_DIR}/}"

        log "  package.json: ${rel_path}"
        append_scan_file nodejs package.json "${manifest}"

        # Skip if no lock file — we can't reliably resolve transitive deps
        if [[ ! -f "${manifest_dir}/package-lock.json" && ! -f "${manifest_dir}/yarn.lock" ]]; then
            log "  No lock file found alongside ${rel_path} — skipping transitive resolution"
        fi

        # Extract dependencies via CycloneDX (includes transitive graph)
        local cdx_output
        if cdx_output=$(cd "${manifest_dir}" && \
            cyclonedx-npm \
                --output-format json \
                --output-reproducible \
                --ignore-npm-errors \
                2>/dev/null); then

            # Parse components from CycloneDX BOM
            local deps
            deps=$(echo "${cdx_output}" | jq '[
                .components[]? |
                {
                    ecosystem: "nodejs",
                    name:      .name,
                    version:   .version,
                    purl:      .purl,
                    licenses:  ([.licenses[]?.expression // .licenses[]?.license.id] | unique),
                    manifest_file: "package.json",
                    manifest_path: "'"${rel_path%/package.json}"'"
                }
            ]')
            append_deps "${deps}"
        else
            record_error nodejs "${rel_path}" "cyclonedx-npm failed"
        fi

        # Also emit license data via license-checker
        local lc_output
        if lc_output=$(cd "${manifest_dir}" && \
            license-checker-rseidelsohn \
                --json \
                --excludePrivatePackages \
                --relativeLicensePath \
                2>/dev/null); then
            log "  license-checker: $(echo "${lc_output}" | jq 'length') packages found"
        fi

    done < <(find_manifests "${WORK_DIR}" "package.json" | grep -v node_modules)
}

# ---------------------------------------------------------------------------
# Python parser
# ---------------------------------------------------------------------------
parse_python() {
    log "Scanning Python manifests…"

    # requirements.txt
    while IFS= read -r req_file; do
        local rel_path="${req_file#${WORK_DIR}/}"
        log "  requirements.txt: ${rel_path}"
        append_scan_file python requirements.txt "${req_file}"

        local audit_output
        if audit_output=$(pip-audit \
                --requirement "${req_file}" \
                --format json \
                --disable-pip \
                2>/dev/null); then
            local deps
            deps=$(echo "${audit_output}" | jq '[
                .dependencies[]? |
                {
                    ecosystem:     "python",
                    name:          .name,
                    version:       .version,
                    purl:          ("pkg:pypi/" + .name + "@" + .version),
                    vulnerabilities: [.vulns[]? | {id:.id, fix_versions:.fix_versions}],
                    manifest_file: "requirements.txt",
                    manifest_path: "'"${rel_path%/requirements.txt}"'"
                }
            ]')
            append_deps "${deps}"
        else
            record_error python "${rel_path}" "pip-audit failed"
        fi
    done < <(find_manifests "${WORK_DIR}" "requirements.txt")

    # pyproject.toml
    while IFS= read -r pyproject; do
        local rel_path="${pyproject#${WORK_DIR}/}"
        log "  pyproject.toml: ${rel_path}"
        append_scan_file python pyproject.toml "${pyproject}"

        local audit_output
        if audit_output=$(pip-audit \
                --requirement "${pyproject}" \
                --format json \
                --disable-pip \
                2>/dev/null); then
            local deps
            deps=$(echo "${audit_output}" | jq '[
                .dependencies[]? |
                {
                    ecosystem:     "python",
                    name:          .name,
                    version:       .version,
                    purl:          ("pkg:pypi/" + .name + "@" + .version),
                    vulnerabilities: [.vulns[]? | {id:.id, fix_versions:.fix_versions}],
                    manifest_file: "pyproject.toml",
                    manifest_path: "'"${rel_path%/pyproject.toml}"'"
                }
            ]')
            append_deps "${deps}"
        else
            record_error python "${rel_path}" "pip-audit failed on pyproject.toml"
        fi
    done < <(find_manifests "${WORK_DIR}" "pyproject.toml")
}

# ---------------------------------------------------------------------------
# Ecosystem dispatch
# ---------------------------------------------------------------------------
IFS=',' read -ra ECOSYSTEMS_ARR <<< "${ECOSYSTEMS}"

for eco in "${ECOSYSTEMS_ARR[@]}"; do
    case "${eco}" in
        nodejs) parse_nodejs ;;
        python) parse_python ;;
        *) log "WARN: unsupported ecosystem '${eco}' — skipping" ;;
    esac
done

# ---------------------------------------------------------------------------
# Emit result JSON to stdout (single line — worker reads tail -1)
# ---------------------------------------------------------------------------
RESULT=$(jq -n \
    --arg    scan_id      "${SCAN_ID}" \
    --argjson deps        "${DEPS_JSON}" \
    --argjson scan_files  "${SCAN_FILES_JSON}" \
    --argjson errors      "${PARSE_ERRORS_JSON}" \
    --argjson dep_count   "$(echo "${DEPS_JSON}" | jq 'length')" \
    '{
        scan_id:        $scan_id,
        status:         "completed",
        total_deps:     $dep_count,
        dependencies:   $deps,
        scan_files:     $scan_files,
        parse_errors:   $errors
    }')

echo "${RESULT}"
log "Scan completed — ${RESULT}" | jq -r '"total_deps=\(.total_deps) errors=\(.parse_errors|length)"' 2>/dev/null || true
