#!/bin/bash
# ci/verify-cmake-lint.sh - CCU-SEC-DSN-CR-005 §4.1/§9
#
# Static build-contract check for CMakeLists.txt:
#   * cmake >= 3.24, versioned project with LANGUAGES CXX
#   * cxx_std_17 via target_compile_features
#   * installed Framework package only (CONFIG + imported targets)
#   * GNUInstallDirs, production target ccu_sec, ccu-sec-runtime component
#   * BUILD_TESTING guards GTest/tests/examples
#   * explicit USE_MOCK_SOMEIP / CCU_SEC_ENABLE_SOFTWARE_HSM options
#   * no compiler/sysroot/target-triple/HOST absolute path/global flags
#
# Exit: 0 = pass, 1 = violation.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CML="${ROOT}/CMakeLists.txt"
STATUS=0

violation() { echo "[FAIL] $1" >&2; STATUS=1; }
ok()        { echo "[OK]   $1"; }

[ -f "$CML" ] || { echo "[FAIL] CMakeLists.txt not found" >&2; exit 1; }

grep -qE '^cmake_minimum_required\(VERSION 3\.2[4-9][^0-9]' "$CML" \
    && ok "cmake_minimum_required >= 3.24" || violation "cmake_minimum_required < 3.24"
grep -qE '^project\(CcuSecService VERSION [0-9]+.*LANGUAGES CXX\)' "$CML" \
    && ok "project versioned with LANGUAGES CXX" || violation "project() not versioned/typed"
grep -q 'target_compile_features.*cxx_std_17' "$CML" \
    && ok "cxx_std_17 via target_compile_features" || violation "cxx_std_17 not set via target_compile_features"
grep -q 'find_package(CCUFramework CONFIG REQUIRED)' "$CML" \
    && ok "find_package(CCUFramework CONFIG REQUIRED)" || violation "framework not consumed via find_package CONFIG"
grep -q 'CCUFramework::ccu-framework-log' "$CML" \
    && ok "imports CCUFramework::ccu-framework-log (installed export)" || violation "missing installed framework target link"
grep -q 'include(GNUInstallDirs)' "$CML" \
    && ok "GNUInstallDirs included" || violation "GNUInstallDirs not used"
grep -qE 'add_executable\(ccu_sec\b' "$CML" \
    && ok "production daemon target ccu_sec" || violation "production target not ccu_sec"
grep -q 'COMPONENT ccu-sec-runtime' "$CML" \
    && ok "install component ccu-sec-runtime" || violation "missing ccu-sec-runtime install component"
grep -q 'CMAKE_INSTALL_FULL_SYSCONFDIR' "$CML" \
    && ok "config uses FULL_SYSCONFDIR (FHS /etc via /usr special-case)" || violation "config not using FULL_SYSCONFDIR"
grep -q 'if(BUILD_TESTING)' "$CML" \
    && ok "tests guarded by BUILD_TESTING" || violation "missing BUILD_TESTING guard"
grep -q 'option(USE_MOCK_SOMEIP' "$CML" \
    && ok "USE_MOCK_SOMEIP is an explicit option" || violation "USE_MOCK_SOMEIP not explicit"
grep -q 'option(CCU_SEC_ENABLE_SOFTWARE_HSM' "$CML" \
    && ok "CCU_SEC_ENABLE_SOFTWARE_HSM is an explicit option" || violation "software HSM switch not explicit"
grep -q 'software HSM fixture' "$CML" \
    && ok "software HSM documented as NON_PRODUCTION fixture" || violation "software HSM fixture not marked non-production"

# GTest must only be looked up inside the BUILD_TESTING block.
GTEST_LINE=$(grep -n 'find_package(GTest' "$CML" | head -1 | cut -d: -f1 || true)
GUARD_LINE=$(grep -n 'if(BUILD_TESTING)' "$CML" | head -1 | cut -d: -f1 || true)
if [ -n "$GTEST_LINE" ] && [ -n "$GUARD_LINE" ] && [ "$GTEST_LINE" -gt "$GUARD_LINE" ]; then
    ok "find_package(GTest) is inside BUILD_TESTING"
else
    violation "GTest looked up outside BUILD_TESTING"
fi

# --- forbidden negatives ---
NCML="$(grep -vE '^[[:space:]]*#' "$CML")"
if echo "$NCML" | grep -qE 'set\(CMAKE_CXX_FLAGS|add_compile_options\(|^[[:space:]]*include_directories\(' ; then
    violation "global CMAKE_CXX_FLAGS / add_compile_options / include_directories (must stay target-scoped)"
fi
if echo "$NCML" | grep -qE 'set\(CMAKE_CXX_COMPILER|CMAKE_TOOLCHAIN_FILE|CMAKE_SYSROOT|CMAKE_FIND_ROOT_PATH|CMAKE_SYSTEM_PROCESSOR' ; then
    violation "sets compiler/sysroot/target-triple/HOST processor selection (must come from CCU-BUILD toolchain)"
fi
if echo "$NCML" | grep -qE 'OPENSSL_ROOT_DIR|OPENSSL_CRYPTO_LIBRARY|OPENSSL_SSL_LIBRARY' ; then
    violation "hard-codes OpenSSL find roots (must come from CCU-BUILD controlled roots)"
fi
if echo "$NCML" | grep -qE 'add_subdirectory\(.*([Ff]ramework|CCU-FW|CCU-Framework)' ; then
    violation "add_subdirectory(framework) forbidden (consume installed SDK only)"
fi
if echo "$NCML" | grep -qE 'link_directories\(' ; then
    violation "link_directories forbidden"
fi
if echo "$NCML" | grep -qE '\$\{PROJECT_SOURCE_DIR\}/third_party|/usr/local|/opt/|\$HOME' ; then
    violation "host/personal absolute path in CMake"
fi
if echo "$NCML" | grep -qE 'install\(TARGETS ccu_sec_lib|install\(TARGETS.*CcuSecTests|install\(TARGETS.*simple_client' ; then
    violation "internal lib / tests / examples must not be installed"
fi
if echo "$NCML" | grep -qE 'install\((FILES|DIRECTORY).*(config/dev|tests/|examples/)' ; then
    violation "install rule references dev fixtures/tests/examples"
fi
# Production install must not pull the software HSM source when disabled.
grep -q 'if(CCU_SEC_ENABLE_SOFTWARE_HSM)' "$CML" \
    && ok "software HSM source is conditionally compiled" || violation "software HSM source not conditionally compiled"

[ "$STATUS" -eq 0 ] && echo "cmake-lint: PASS" || echo "cmake-lint: FAIL"
exit $STATUS
