#!/bin/bash
# scripts/build.sh - HOST/dev build + test (NON_PRODUCTION mock backend)
#
# Production TARGET builds are driven by CCU-BUILD with
# BUILD_TESTING=OFF, USE_MOCK_SOMEIP=OFF and CCU_SEC_ENABLE_SOFTWARE_HSM=OFF
# (CCU-SEC-DSN-CR-005 §4.1). This script is HOST/dev only.
#
# OpenSSL must come from a BUILD-controlled find root. Set OPENSSL_ROOT_DIR
# (e.g. /opt/homebrew/opt/openssl on macOS) when the system default has no
# OpenSSL development package.

set -e

BUILD_DIR="build"
BUILD_TYPE="Debug"

OPENSSL_ARGS=()
if [[ -n "${OPENSSL_ROOT_DIR:-}" ]]; then
    OPENSSL_ARGS=(-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR")
fi

# Clean build directory
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure: explicit HOST/dev inputs, never HOST auto-detection
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DBUILD_TESTING=ON \
      -DUSE_MOCK_SOMEIP=ON \
      -DCCU_SEC_ENABLE_SOFTWARE_HSM=ON \
      "${OPENSSL_ARGS[@]}" ..

# Build
if [[ "$(uname)" == "Darwin" ]]; then
    JOBS=$(sysctl -n hw.ncpu)
else
    JOBS=$(nproc)
fi
make -j$JOBS

# Run tests
ctest --output-on-failure

echo "Build and tests completed successfully!"
