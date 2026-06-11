# se-driver differential-test oracle

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
