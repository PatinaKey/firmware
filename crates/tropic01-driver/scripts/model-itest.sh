#!/usr/bin/env bash
# Live integration tests against the official TROPIC01 model (ts-tvl).
#
# Starts the model server, runs the feature-gated `model-itest` suite against
# it (the tropic01-driver public API driven over a TCP shim), then tears the server
# down. These are NOT part of the normal `cargo test` or CI: they need Python,
# the model wheel, and a TCP service, so they stay an on-demand local gate.
#
# HOST TEST ONLY. Validates protocol byte-exactness, not physical security.
#
# Prerequisite (one-time): install the model into a venv with the official
# installer, then point LIBTROPIC at your libtropic checkout:
#
#   "$LIBTROPIC/scripts/tropic01_model/install_linux.sh"
#   export LIBTROPIC=/path/to/libtropic
#   crates/tropic01-driver/scripts/model-itest.sh
#
# The model server pins the chip secrets from model_cfg.yml (chip static key +
# pairing slot 0 = the libtropic prod0 test keypair), which the tests hardcode.

set -euo pipefail

LT="${LIBTROPIC:?set LIBTROPIC to your libtropic checkout (the model lives at scripts/tropic01_model)}"
MODEL_DIR="$LT/scripts/tropic01_model"
MODEL_SERVER="$MODEL_DIR/.venv/bin/model_server"
MODEL_CFG="$MODEL_DIR/model_cfg.yml"
MODEL_HOST="127.0.0.1"
MODEL_PORT="28992"

if [[ ! -x "$MODEL_SERVER" ]]; then
    echo "model_server not found at $MODEL_SERVER" >&2
    echo "Run $MODEL_DIR/install_linux.sh first." >&2
    exit 1
fi

# Resolve the firmware crate root (this script lives in firmware/scripts).
# This script lives in crates/tropic01-driver/scripts; the crate manifest is one level up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(dirname "$SCRIPT_DIR")"

SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Starting TROPIC01 model server..."
"$MODEL_SERVER" tcp -c "$MODEL_CFG" -o /tmp/model-itest-save.yml >/tmp/model-itest-server.log 2>&1 &
SERVER_PID=$!

# Wait for the TCP port to accept connections (up to ~10s).
for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/$MODEL_HOST/$MODEL_PORT") 2>/dev/null; then
        exec 3>&- 3<&-
        break
    fi
    sleep 0.2
done

echo "Running model integration tests..."
# Single-threaded: the model is one stateful target. Each test resets it first.
cargo test --manifest-path "$CRATE_DIR/Cargo.toml" \
    --features model-itest -- --test-threads=1 "$@"

echo "Model integration tests passed."
