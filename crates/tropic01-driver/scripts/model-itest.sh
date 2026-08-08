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
# Prerequisite (one-time): point LIBTROPIC at your libtropic checkout, then
# install the pinned model wheel into its venv:
#
#   export LIBTROPIC=/path/to/libtropic
#   crates/tropic01-driver/scripts/install-model.sh
#   crates/tropic01-driver/scripts/model-itest.sh
#
# The model server pins the chip secrets from model_cfg.yml (chip static key +
# pairing slot 0 = the libtropic prod0 test keypair), which the tests hardcode.

set -euo pipefail

LT="${LIBTROPIC:?set LIBTROPIC to your libtropic checkout (the model lives at scripts/tropic01_model)}"
MODEL_DIR="$LT/scripts/tropic01_model"
MODEL_VENV="$MODEL_DIR/.venv"
MODEL_SERVER="$MODEL_VENV/bin/model_server"
MODEL_CFG="$MODEL_DIR/model_cfg.yml"
MODEL_HOST="127.0.0.1"
MODEL_PORT="28992"

# Resolve the driver crate root. This script lives in
# crates/tropic01-driver/scripts, so the crate manifest is one level up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(dirname "$SCRIPT_DIR")"
INSTALLER="$SCRIPT_DIR/install-model.sh"

if [[ ! -x "$MODEL_SERVER" ]]; then
    echo "model_server not found at $MODEL_SERVER" >&2
    echo "Run $INSTALLER first." >&2
    exit 1
fi

# The version pin lives in install-model.sh, this only enforces it.
WANT_VERSION="$(sed -n 's/^TVL_VERSION="\(.*\)"$/\1/p' "$INSTALLER")"
HAVE_VERSION="$("$MODEL_VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("tvl"))')"
if [[ "$WANT_VERSION" != "$HAVE_VERSION" ]]; then
    echo "model venv has ts-tvl $HAVE_VERSION, this repository pins $WANT_VERSION" >&2
    echo "Run $INSTALLER to update it." >&2
    exit 1
fi

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
