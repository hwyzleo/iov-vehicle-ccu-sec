#!/bin/bash
# tests/smoke/smoke-sec.sh - CCU-SEC-DSN-CR-005 §8.2/§9 smoke entry
#
# Canonical smoke test referenced by the CCU-BUILD service manifest
# (smoke_test: tests/smoke/smoke-sec.sh).
#
# HOST scope (this script, NON_PRODUCTION software SE/HSM fixture):
#   * daemon starts from a temp config root (no source-tree WorkingDirectory)
#   * unified sec.yaml + BUILD-style common.yaml load successfully
#   * mock SOME/IP provider initializes and reaches the main loop
#   * SIGTERM triggers bounded clean shutdown within the unit TimeoutStopSec
#   * no secret material is emitted into the daemon log
#
# TARGET scope (run by CCU-BUILD): daemon-reload, start/stop/restart,
# SOME/IP offer against the real backend, DIAG/FOTA -> SEC calls, missing root /
# authorization failure, zero-leak audit and preserve-rollback on a machine with
# an approved SE/HSM. That acceptance is NOT replaced by this HOST script.
#
# Usage: tests/smoke/smoke-sec.sh [--build-dir <dir>] [--show-logs]
# Exit: 0 = pass, 1 = fail

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${CCU_SEC_BUILD_DIR:-${PROJECT_ROOT}/build}"

SEC_LOG=""
SMOKE_TMP=""
SEC_PID=""

# packaging/systemd/ccu-sec.service TimeoutStopSec=30s; allow a small margin.
STOP_BUDGET_S=35
READY_WAIT_S=4

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; }

cleanup() {
    if [ -n "$SEC_PID" ] && kill -0 "$SEC_PID" 2>/dev/null; then
        kill "$SEC_PID" 2>/dev/null || true
        wait "$SEC_PID" 2>/dev/null || true
    fi
    [ -n "$SMOKE_TMP" ] && rm -rf "$SMOKE_TMP"
}
trap cleanup EXIT INT TERM

SHOW_LOGS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --show-logs) SHOW_LOGS=true; shift ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --help) echo "Usage: $0 [--build-dir <dir>] [--show-logs]"; exit 0 ;;
        *) fail "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ "$BUILD_DIR" != /* ]]; then
    BUILD_DIR="${PROJECT_ROOT}/${BUILD_DIR}"
fi
SEC_BIN="${BUILD_DIR}/ccu_sec"
if [ ! -x "$SEC_BIN" ]; then
    fail "ccu_sec executable not found at ${SEC_BIN}. Build first."
    exit 1
fi

# --- temp config root (BUILD-style layout: common.yaml + conf.d/sec.yaml) ---
SMOKE_TMP="$(mktemp -d -t sec-smoke.XXXXXX)"
mkdir -p "${SMOKE_TMP}/conf.d"
cp "${PROJECT_ROOT}/config/dev/common.yaml" "${SMOKE_TMP}/common.yaml"
cp "${PROJECT_ROOT}/config/dev/sec.yaml" "${SMOKE_TMP}/conf.d/sec.yaml"
SEC_LOG="${SMOKE_TMP}/daemon.log"

# Pick an ephemeral port so parallel/local runs do not collide on 51140, and
# rewrite the NON_PRODUCTION mock network fixture accordingly.
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
python3 - "$PORT" "${PROJECT_ROOT}/config/dev/vsomeip.json" \
    "${SMOKE_TMP}/vsomeip.json" <<'PY'
import json, sys
port, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.load(open(src))
data["services"][0]["reliable"]["port"] = port
data["services"][0]["unreliable"] = port
data["logging"]["file"]["enable"] = False
json.dump(data, open(dst, "w"), indent=2)
PY

# --- start from the temp config root, not the source tree ---
info "Starting ccu_sec with temp config root (no source-tree cwd)..."
( cd "$SMOKE_TMP" && exec "$SEC_BIN" \
    --sec-config "${SMOKE_TMP}/conf.d/sec.yaml" \
    --common-config "${SMOKE_TMP}/common.yaml" \
    --vsomeip-config "${SMOKE_TMP}/vsomeip.json" \
    > "$SEC_LOG" 2>&1 ) &
SEC_PID=$!

# --- readiness: any config/logger/adapter failure exits immediately ---
info "Waiting ${READY_WAIT_S}s for daemon init..."
sleep "$READY_WAIT_S"
if ! kill -0 "$SEC_PID" 2>/dev/null; then
    fail "ccu_sec exited during init (config/logger/SE-HSM failure, fail-closed)"
    [ -s "$SEC_LOG" ] && { echo "=== sec log ==="; cat "$SEC_LOG"; }
    exit 1
fi
success "ccu_sec running (unified config + logger + SE/HSM + SOME/IP init passed)"

# Prove the mock provider is actually listening (business offer evidence).
if python3 - "$PORT" <<'PROBE'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 5
while time.time() < deadline:
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        sys.exit(0)
    except OSError:
        s.close()
        time.sleep(0.2)
sys.exit(1)
PROBE
then
    success "SOME/IP provider listening on 127.0.0.1:${PORT}"
else
    fail "SOME/IP provider not reachable on 127.0.0.1:${PORT}"
    exit 1
fi

# --- SIGTERM -> bounded clean shutdown (unit TimeoutStopSec budget) ---
info "Sending SIGTERM, expecting clean shutdown within ${STOP_BUDGET_S}s..."
t0=$(date +%s)
kill -TERM "$SEC_PID" 2>/dev/null
deadline=$((t0 + STOP_BUDGET_S))
while kill -0 "$SEC_PID" 2>/dev/null; do
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
        fail "ccu_sec did not stop within ${STOP_BUDGET_S}s (TimeoutStopSec budget)"
        kill -KILL "$SEC_PID" 2>/dev/null || true
        wait "$SEC_PID" 2>/dev/null || true
        [ -s "$SEC_LOG" ] && { echo "=== sec log ==="; cat "$SEC_LOG"; }
        exit 1
    fi
    sleep 1
done
t1=$(date +%s)
success "ccu_sec stopped cleanly in $((t1 - t0))s (within TimeoutStopSec budget)"

# --- evidence: initialized + provider + clean stop, and zero secret leakage ---
if [ -s "$SEC_LOG" ] && grep -q "CCU-SEC service initialized" "$SEC_LOG"; then
    success "sec.service.initialized recorded"
else
    fail "sec.service.initialized evidence missing in log"
    [ -s "$SEC_LOG" ] && { echo "=== sec log ==="; cat "$SEC_LOG"; }
    exit 1
fi
if [ -s "$SEC_LOG" ] && grep -q "CCU-SEC service stopped" "$SEC_LOG"; then
    success "clean shutdown recorded"
else
    fail "clean shutdown evidence missing in log"
    [ -s "$SEC_LOG" ] && { echo "=== sec log ==="; cat "$SEC_LOG"; }
    exit 1
fi

# NON_PRODUCTION fixture must never claim security readiness.
if [ -s "$SEC_LOG" ] && grep -qi "security_ready=true" "$SEC_LOG"; then
    fail "software fixture claimed security_ready=true (must stay unready)"
    exit 1
fi
success "security capability correctly reported as not ready (non-production fixture)"

# Zero-leak scan: no key material / key names / seed values in the log.
if python3 - "$SEC_LOG" <<'LEAK'
import re, sys
text = open(sys.argv[1], errors="ignore").read()
patterns = [
    r"OTA_VEHICLE_ROOT", r"CCU_DEVICE_ROOT", r"DIAG_SEEDKEY_SECRET",
    r"key_files", r"session_key=", r"private_key", r"0x42",
]
hits = [p for p in patterns if re.search(p, text)]
if hits:
    print("sensitive token(s) found in log: " + ", ".join(hits))
    sys.exit(1)
sys.exit(0)
LEAK
then
    success "zero-leak log scan passed"
else
    fail "specific key material / logical key names leaked into the log"
    [ -s "$SEC_LOG" ] && { echo "=== sec log ==="; cat "$SEC_LOG"; }
    exit 1
fi

if [ "$SHOW_LOGS" = true ] && [ -s "$SEC_LOG" ]; then
    echo "=== sec log ==="; cat "$SEC_LOG"
fi

success "smoke-sec PASSED"
exit 0
