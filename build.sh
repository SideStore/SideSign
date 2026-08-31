#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

{
    echo "=== Building SideSign (release) ==="
    echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo ""

    swift build -c release --product sidesign
    BIN_PATH="$(swift build -c release --show-bin-path)/sidesign"
    cp "$BIN_PATH" ./sidesign

    echo ""
    echo "=== Build Complete! Binary copied to ./sidesign ==="
} 2>&1 | tee build.log
