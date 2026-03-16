#!/bin/bash
# NGFW Build Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "========================================"
echo "NGFW Build Script"
echo "========================================"

ARCH="${ARCH:-x86_64}"
CLEAN="${CLEAN:-no}"

if [ "$CLEAN" = "yes" ]; then
    echo "Cleaning build..."
    make clean
fi

echo "Building for ARCH=$ARCH..."

if [ "$1" = "test" ]; then
    echo "Building and running tests..."
    make test
    ./tests/ngfw_test
elif [ "$1" = "install" ]; then
    echo "Installing..."
    make install PREFIX="$2"
else
    echo "Building library..."
    make ARCH="$ARCH"
    
    echo "Building executable..."
    make ngfw ARCH="$ARCH"
    
    echo "Build complete!"
    echo "  Library: libngfw.a"
    echo "  Executable: ngfw"
    echo "  Tests: tests/ngfw_test"
fi
