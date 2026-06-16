# tropic01-driver differential-test oracle

The official C `libtropic` is the protocol ground truth. It is NEVER linked into
the firmware. It is used OFF-TARGET to generate golden vectors that the Rust
driver is asserted against (differential testing).

## Handshake key-schedule KAT (`hs_oracle.c`)

Reproduces libtropic's `lt_in__session_start` key derivation byte-for-byte using
the REAL libtropic functions (`lt_X25519`, `lt_hkdf`, `lt_sha256`) with the
openssl crypto backend, over PINNED test inputs. Emits golden `kCMD`/`kRES`/
`kAUTH`/`h` plus a valid `t_tauth`. The Rust handshake KAT test hardcodes these
and asserts byte-for-byte equality. Regenerate ONLY on a libtropic tag bump.

### Build & run (Linux, needs libcrypto)

`LT` is the path to a checkout of the official libtropic C SDK (pinned to the
conformance tag). It is an external, read-only reference and is NOT part of this
repository.

```
LT=/path/to/libtropic
gcc -O2 -w -o /tmp/hs_oracle hs_oracle.c \
  "$LT/src/lt_hkdf.c" "$LT/src/libtropic_secure_memzero.c" \
  "$LT/cal/openssl/lt_openssl_sha256.c" "$LT/cal/openssl/lt_openssl_hmac_sha256.c" \
  "$LT/cal/openssl/lt_openssl_x25519.c" \
  -I"$LT/include" -I"$LT/src" -I"$LT/cal/openssl" -lcrypto
/tmp/hs_oracle
```

### Golden vectors (libtropic, openssl backend, captured 2026-06-10)

Pinned inputs (NOT production keys):
- EHPRIV  = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
- EHPUB   = 07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c
- SHIPRIV = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
- SHIPUB  = 5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b
- STPRIV  = 6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80
- STPUB   = 244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49
- ETPRIV  = 4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60
- ETPUB   = 64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466
- PKEY_INDEX = 0

Golden outputs:
- H_TRANSCRIPT = e61391c0f92f0afaf1e29c9483833dc925aa5fb790f2e61597c90a63d6c57be4
- KCMD    = 37bce877e9d5650607c67c0ea83e8df3ba89a22092b3746ce7a9301ab711d82c
- KRES    = 339beec5e3943a18b6204def5cf59d8bef013862e0d863324d32a176472be8d7
- KAUTH   = 168a193996fdeaace79a0c878c246a6fd0ec61d3273fb7805f0c31b08c3158aa
- T_TAUTH = 8c0ab7c77d48e6d224fd6bd46d8cd53a

CRITICAL key-schedule subtlety (do not "fix"): the FIRST HKDF call uses the
32-byte `protocol_name` as the chaining key (`ck_len = 32`). Every subsequent
call uses the 33-byte `output_1` buffer (`ck_len = 33`, last byte always zero).
HMAC over a 32- vs 33-byte key gives different results, so this must be exact.

## L2 SEND multi-chunk KAT (`l2_frame_capture.c`)

Captures REAL libtropic L2 frames on the wire and pins them as golden vectors
for the Rust L2 SEND chunker. This breaks the chip-mock circularity for the
SEND path: the residual unverified-vs-silicon surface was the L2 frame length
encoding and the 252-byte chunk constant. The golden frames come from an
independent implementation (libtropic C plus the official TROPIC01 model), so a
wrong chunk boundary, REQ_LEN byte, or CRC fails the comparison.

The capture runs a full session against the official TROPIC01 model
(`ts-tvl`, Tropic Square's software emulator: TCP `127.0.0.1:28992`, no
hardware) and dumps every L1 SPI frame via libtropic's `LT_PRINT_SPI_DATA`. The
sequence is a 600-byte Ping (whose 619-byte L3 packet spans 252 + 252 + 115
byte chunks) plus a 16-byte Random_Get (one 20-byte chunk).

### Capture procedure (Linux)

`LT` is a checkout of the official libtropic C SDK (pinned to the conformance
tag). It is an external, read-only reference and is NOT part of this repository.

```
# 1. Install the model (downloads the ts-tvl wheel into a venv).
LT=/path/to/libtropic
"$LT/scripts/tropic01_model/install_linux.sh"

# 2. Drop l2_frame_capture.c into a model example and build with SPI printing.
mkdir -p "$LT/examples/model/kat_capture"
cp l2_frame_capture.c "$LT/examples/model/kat_capture/main.c"
cp "$LT/examples/model/hello_world/CMakeLists.txt" \
   "$LT/examples/model/kat_capture/CMakeLists.txt"   # then s/hello_world/kat_capture/
cmake -S "$LT/examples/model/kat_capture" -B build -G Ninja -DLT_PRINT_SPI_DATA=ON
cmake --build build

# 3. Run the model with the pinned config, then the capture binary.
"$LT/scripts/tropic01_model/.venv/bin/model_server" tcp \
   -c "$LT/scripts/tropic01_model/model_cfg.yml" &
./build/libtropic_kat_capture            # dumps "SPI >> TX" / "<< RX" hex lines
```

The `>> TX` frames between the `KAT-MARK ping-begin`/`ping-end` markers are the
3 multi-chunk SEND frames. The one between `random-begin`/`random-end` is the
single-chunk SEND frame. Each frame is `[REQ_ID(0x04) | REQ_LEN | REQ_DATA |
CRC(2)]`. The frames are pinned as `PING_FRAME_0..2` and `RANDOM_FRAME` in
`src/l2/transport.rs`. The Rust test reconstructs the contiguous L3 packet from
the chunk data fields, runs the chunker, and asserts byte-identical frames.

NOTE: this validates PROTOCOL byte-exactness only. The session keys are NOT
pinned (libtropic's host ephemeral comes from its PSA RNG), so the ciphertext
bytes differ run-to-run. The FRAMING (boundaries, lengths, CRC) is what is
asserted and is deterministic from the L3 packet length. A full reproducible
end-to-end transcript (asserting ciphertext too) would additionally require
pinning libtropic's host ephemeral via its crypto backend. Regenerate the frames
only on a libtropic tag bump. The chunk math is stable across captures.

This is a HOST test tool. It does NOT validate physical security (timing, the
real TRNG, the real MAC-and-Destroy KDF, or DPA resistance).
