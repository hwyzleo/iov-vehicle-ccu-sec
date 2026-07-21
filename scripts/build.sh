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
make -j$(nproc)

# Run tests
ctest --output-on-failure

echo "Build and tests completed successfully!"
