#!/bin/bash
# ci/run-ci-gates.sh - CCU-SEC-DSN-CR-005 §9 commit-level CI gates
#
# Runs SEC's CR-005 HOST/commit gates in order:
#   1. CMake build-contract lint
#   2. systemd baseline unit contract
#   3. unified sec.yaml schema + cross-field/secret checks (positive + negative
#      + release-profile placeholder rejection)
#   4. configure + build + unit/contract tests (HOST, mock SOME/IP, software HSM)
#   5. installed Framework SDK consumer (relocatable find_package + link)
#   6. production configure (BUILD_TESTING=OFF, software HSM OFF) proves GTest,
#      test targets and the software SE/HSM fixture are absent
#   7. DESTDIR install + exact ccu-sec-runtime manifest + repeat-install digest
#   8. daemon lifecycle smoke (temp config root -> SIGTERM bounded stop,
#      zero-leak log scan)
#   9. fail-closed gate: no approved adapter / unconfigured placeholder refuses
#      to start, no key generation and no provider offer
#
# TARGET cross-compile / ELF / ABI / NEEDED / RPATH / approved-SE-HSM business
# smoke / provisioning preserve-rollback are run by CCU-BUILD and are not
# replaced here.
#
# Usage: ci/run-ci-gates.sh [--sdk-prefix <dir>] [--build-dir <dir>]
#                           [--openssl-root <dir>]
# Exit: 0 = all pass, 1 = any gate failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_PREFIX="${CCU_FRAMEWORK_PREFIX:-$HOME/.local}"
BUILD_DIR="${ROOT}/build-ci"
PROD_BUILD_DIR="${ROOT}/build-ci-prod"
OPENSSL_ROOT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --sdk-prefix)   SDK_PREFIX="$2"; shift 2 ;;
        --build-dir)    BUILD_DIR="$2"; shift 2 ;;
        --openssl-root) OPENSSL_ROOT="$2"; shift 2 ;;
        --help) echo "Usage: $0 [--sdk-prefix <dir>] [--build-dir <dir>] [--openssl-root <dir>]"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# OpenSSL is resolved only from BUILD-controlled find roots; the project never
# hard-codes a host path (CCU-SEC-DSN-CR-005 §4.1).
OPENSSL_ARGS=()
if [ -n "$OPENSSL_ROOT" ]; then
    OPENSSL_ARGS=(-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT")
elif [ -n "${OPENSSL_ROOT_DIR:-}" ]; then
    OPENSSL_ARGS=(-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR")
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
gate() { echo -e "\n${BLUE}=== GATE $1: $2 ===${NC}"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }

FAILURES=0
run() {
    local name="$1"; shift
    if "$@"; then pass "$name"; else fail "$name"; FAILURES=$((FAILURES+1)); fi
}

schema_ok() {
    local profile="$1" f="$2"
    python3 "${ROOT}/ci/verify-config-schema.py" --profile "$profile" "$f" \
        >/dev/null 2>&1
}

configure() {
    local build_dir="$1" testing="$2" software_hsm="$3"
    cmake -S "$ROOT" -B "$build_dir" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_TESTING="$testing" \
        -DUSE_MOCK_SOMEIP=ON \
        -DCCU_SEC_ENABLE_SOFTWARE_HSM="$software_hsm" \
        -DCMAKE_PREFIX_PATH="$SDK_PREFIX" \
        -DCCUFramework_DIR="$SDK_PREFIX/lib/cmake/CCUFramework" \
        "${OPENSSL_ARGS[@]}" >/dev/null 2>&1
}

# 1. CMake lint
gate 1 "CMake build-contract lint"
run "cmake-lint" bash "${ROOT}/ci/verify-cmake-lint.sh"

# 2. systemd unit
gate 2 "systemd baseline unit contract"
run "systemd-unit" bash "${ROOT}/ci/verify-systemd-unit.sh"

# 3. unified config schema
gate 3 "unified sec.yaml schema + checks"
run "schema-default" python3 "${ROOT}/ci/verify-config-schema.py" \
    "${ROOT}/config/sec.default.yaml"
run "schema-dev" python3 "${ROOT}/ci/verify-config-schema.py" \
    "${ROOT}/config/dev/sec.yaml"
NEG_FAILURES=0
for f in "${ROOT}"/tests/config/invalid_*.yaml; do
    if schema_ok default "$f"; then
        fail "negative schema case unexpectedly passed: $(basename "$f")"
        NEG_FAILURES=$((NEG_FAILURES+1))
    else
        pass "negative schema rejected: $(basename "$f")"
    fi
done
for f in "${ROOT}/config/sec.default.yaml" "${ROOT}/config/dev/sec.yaml"; do
    if schema_ok release "$f"; then
        fail "release profile accepted non-production HSM state: $(basename "$f")"
        NEG_FAILURES=$((NEG_FAILURES+1))
    else
        pass "release profile rejects non-production HSM state: $(basename "$f")"
    fi
done
if [ "$NEG_FAILURES" -ne 0 ]; then
    FAILURES=$((FAILURES+1))
fi

# 4. HOST configure + build + tests (NON_PRODUCTION mock backend + fixture)
gate 4 "configure + build + unit/contract tests"
rm -rf "$BUILD_DIR"
if configure "$BUILD_DIR" ON ON \
   && cmake --build "$BUILD_DIR" -j >/dev/null 2>&1 \
   && ctest --test-dir "$BUILD_DIR" --output-on-failure >/dev/null 2>&1; then
    pass "build+tests"
else
    fail "build+tests"; FAILURES=$((FAILURES+1))
fi

# 5. installed Framework SDK consumer
gate 5 "installed Framework SDK consumer"
run "installed-framework-consumer" cmake \
    -DSDK_PREFIX="$SDK_PREFIX" -P "${ROOT}/ci/verify-installed-framework.cmake"

# 6. production configure must not require GTest/tests or the software HSM
gate 6 "production configure (BUILD_TESTING=OFF, software HSM OFF)"
rm -rf "$PROD_BUILD_DIR"
PROD_OK=1
if ! configure "$PROD_BUILD_DIR" OFF OFF; then
    PROD_OK=0
fi
if [ "$PROD_OK" -eq 1 ] && cmake --build "$PROD_BUILD_DIR" --target ccu_sec -j >/dev/null 2>&1; then
    pass "production configure+build without tests"
else
    fail "production configure+build"; PROD_OK=0; FAILURES=$((FAILURES+1))
fi
if [ "$PROD_OK" -eq 1 ]; then
    if grep -qiE 'GTEST|GTest' "$PROD_BUILD_DIR/CMakeCache.txt"; then
        fail "production configure referenced GTest"; FAILURES=$((FAILURES+1))
    else
        pass "production configure did not look up GTest"
    fi
    if cmake --build "$PROD_BUILD_DIR" --target CcuSecTests >/dev/null 2>&1; then
        fail "test target CcuSecTests exists with BUILD_TESTING=OFF"; FAILURES=$((FAILURES+1))
    else
        pass "test targets absent with BUILD_TESTING=OFF"
    fi
    if [ -e "$PROD_BUILD_DIR/CMakeFiles/ccu_sec_lib.dir/src/software_se_hsm.cpp.o" ]; then
        fail "software SE/HSM fixture compiled into the production build"
        FAILURES=$((FAILURES+1))
    else
        pass "software SE/HSM fixture absent from the production build"
    fi
fi

# 7. DESTDIR install manifest + repeat-install digest
gate 7 "DESTDIR install manifest + repeat-install consistency"
ROOT1="$(mktemp -d -t sec-install1.XXXXXX)"
ROOT2="$(mktemp -d -t sec-install2.XXXXXX)"
if env DESTDIR="$ROOT1" cmake --install "$BUILD_DIR" --prefix /usr \
        --component ccu-sec-runtime >/dev/null 2>&1; then
    run "install-manifest" python3 "${ROOT}/ci/verify-install-manifest.py" "$ROOT1"
else
    fail "DESTDIR install"; FAILURES=$((FAILURES+1))
fi
if env DESTDIR="$ROOT2" cmake --install "$BUILD_DIR" --prefix /usr \
        --component ccu-sec-runtime >/dev/null 2>&1; then
    run "install-manifest-repeat" python3 "${ROOT}/ci/verify-install-manifest.py" "$ROOT2"
    if python3 - "$ROOT1" "$ROOT2" <<'PY'
import hashlib, os, stat, sys

def manifest(root):
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            with open(full, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            mode = stat.S_IMODE(os.stat(full).st_mode)
            out[rel] = (digest, mode)
    return out

if manifest(sys.argv[1]) != manifest(sys.argv[2]):
    sys.exit(1)
PY
    then
        pass "clean/incremental install set, mode and digest consistent"
    else
        fail "repeat install differs (set/mode/digest)"; FAILURES=$((FAILURES+1))
    fi
else
    fail "DESTDIR install (repeat)"; FAILURES=$((FAILURES+1))
fi
rm -rf "$ROOT1" "$ROOT2"

# 8. daemon lifecycle smoke
gate 8 "daemon lifecycle smoke"
run "smoke-sec" bash "${ROOT}/tests/smoke/smoke-sec.sh" --build-dir "$BUILD_DIR"

# 9. fail-closed gate (production build without an approved adapter)
gate 9 "fail-closed startup without approved SE/HSM adapter"
PROD_BIN="${PROD_BUILD_DIR}/ccu_sec"
expect_fail_closed() {
    local name="$1" sec_config="$2"
    local log_file
    log_file="$(mktemp -t sec-failclosed.XXXXXX)"
    "$PROD_BIN" \
        --sec-config "$sec_config" \
        --common-config "${ROOT}/config/dev/common.yaml" \
        --vsomeip-config "${ROOT}/config/dev/vsomeip.json" \
        >"$log_file" 2>&1 &
    local pid=$!
    local waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge 8 ]; then
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            fail "$name: process stayed alive (security provider was opened)"
            rm -f "$log_file"
            return 1
        fi
        sleep 1
        waited=$((waited+1))
    done
    wait "$pid" 2>/dev/null
    local rc=$?
    if [ "$rc" -ne 0 ] && grep -qiE 'fail-closed|CCU-SEC-1006' "$log_file"; then
        pass "$name: refused to start (exit ${rc}), fail-closed recorded"
        rm -f "$log_file"
        return 0
    fi
    fail "$name: expected non-zero fail-closed exit, got ${rc}"
    [ -s "$log_file" ] && sed -n '1,20p' "$log_file"
    rm -f "$log_file"
    return 1
}
if [ -x "$PROD_BIN" ] && [ "$PROD_OK" -eq 1 ]; then
    run "fail-closed-unconfigured" expect_fail_closed "sec.se_hsm.type=unconfigured" \
        "${ROOT}/config/sec.default.yaml"
    run "fail-closed-software-not-compiled" expect_fail_closed "sec.se_hsm.type=software (not compiled)" \
        "${ROOT}/config/dev/sec.yaml"
else
    fail "fail-closed gate skipped (production build unavailable)"
    FAILURES=$((FAILURES+1))
fi

echo -e "\n========================================"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}ALL CCU-SEC-DSN-CR-005 HOST CI GATES PASSED${NC}"
    exit 0
else
    echo -e "${RED}${FAILURES} GATE(S) FAILED${NC}"
    exit 1
fi
