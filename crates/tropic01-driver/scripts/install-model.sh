#!/usr/bin/env bash
# Installs the pinned official TROPIC01 model (ts-tvl) for the live integration
# suite.
#
# Usage:
#   export LIBTROPIC=/path/to/libtropic
#   crates/tropic01-driver/scripts/install-model.sh

set -euo pipefail

# Pinned model version.
TVL_VERSION="2.5"
TVL_SHA256="c51c5dd35a6e075d9dd71c17abba53f4669d54cb4b96500295ee279a9c192ed2"
TVL_WHEEL="tvl-${TVL_VERSION}-py3-none-any.whl"
TVL_URL="https://github.com/tropicsquare/ts-tvl/releases/download/${TVL_VERSION}/${TVL_WHEEL}"

LT="${LIBTROPIC:?set LIBTROPIC to your libtropic checkout (the model lives at scripts/tropic01_model)}"
MODEL_DIR="$LT/scripts/tropic01_model"
VENV_DIR="$MODEL_DIR/.venv"

if [[ ! -f "$MODEL_DIR/model_cfg.yml" ]]; then
    echo "model config not found at $MODEL_DIR/model_cfg.yml" >&2
    echo "LIBTROPIC must point at a libtropic checkout." >&2
    exit 1
fi

for tool in sha256sum python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required tool: $tool" >&2
        exit 1
    fi
done

if command -v curl >/dev/null 2>&1; then
    download() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    download() { wget -q -O "$2" "$1"; }
else
    echo "missing required tool: curl or wget" >&2
    exit 1
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    echo "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "Downloading $TVL_WHEEL..."
download "$TVL_URL" "$TMP_DIR/$TVL_WHEEL"

actual="$(sha256sum "$TMP_DIR/$TVL_WHEEL" | awk '{print $1}')"
if [[ "$actual" != "$TVL_SHA256" ]]; then
    echo "wheel checksum mismatch: expected $TVL_SHA256, got $actual" >&2
    exit 1
fi

echo "Installing ts-tvl $TVL_VERSION..."
"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
"$VENV_DIR/bin/python" -m pip install --quiet "$TMP_DIR/$TVL_WHEEL"

installed="$("$VENV_DIR/bin/python" -c 'import importlib.metadata as m; print(m.version("tvl"))')"
if [[ "$installed" != "$TVL_VERSION" ]]; then
    echo "installed ts-tvl is $installed, expected $TVL_VERSION" >&2
    exit 1
fi

echo "TROPIC01 model ts-tvl $TVL_VERSION installed at $VENV_DIR"
