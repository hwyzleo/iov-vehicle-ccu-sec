#!/bin/bash

set -e

BUILD_DIR="build"
BUILD_TYPE="Debug"

# Clean build directory
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Configure
cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE ..

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
