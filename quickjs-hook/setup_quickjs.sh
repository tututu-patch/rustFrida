#!/bin/bash
# Setup script to download QuickJS source files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QUICKJS_DIR="$SCRIPT_DIR/quickjs-src"

if [ -d "$QUICKJS_DIR" ]; then
    echo "QuickJS source directory already exists at $QUICKJS_DIR"
    exit 0
fi

echo "Downloading QuickJS source..."

# Create directory
mkdir -p "$QUICKJS_DIR"
cd "$QUICKJS_DIR"

# Download from bellard's site or GitHub
QUICKJS_VERSION="2024-01-13"
QUICKJS_URL="https://bellard.org/quickjs/quickjs-${QUICKJS_VERSION}.tar.xz"

# Try to download
if command -v curl &> /dev/null; then
    curl -L -o quickjs.tar.xz "$QUICKJS_URL"
elif command -v wget &> /dev/null; then
    wget -O quickjs.tar.xz "$QUICKJS_URL"
else
    echo "Error: Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Extract
if [ -f quickjs.tar.xz ]; then
    tar -xJf quickjs.tar.xz --strip-components=1
    rm quickjs.tar.xz
    echo "QuickJS source downloaded and extracted to $QUICKJS_DIR"
else
    echo "Download failed. Trying GitHub mirror..."

    # Try GitHub mirror
    cd "$SCRIPT_DIR"
    rm -rf "$QUICKJS_DIR"

    if command -v git &> /dev/null; then
        git clone --depth 1 https://github.com/nicovank/quickjs-cmake.git quickjs-tmp
        mkdir -p "$QUICKJS_DIR"
        cp quickjs-tmp/quickjs/*.{c,h} "$QUICKJS_DIR/" 2>/dev/null || true
        rm -rf quickjs-tmp
        echo "QuickJS source cloned from GitHub mirror"
    else
        echo "Error: git not found and download failed."
        exit 1
    fi
fi

echo "Setup complete!"
