//! Integration tests for the `image-signer` binary front end.
//!
//! They run the compiled binary the way an operator would, so the hand-rolled
//! arg parsing, the file reads, and the fail-closed exit codes are all under
//! test. Each test writes its inputs to a unique temp path and cleans up.

use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

use image_verify::ROOT_KEY_LEN;
use sha2::Digest;
use sha2::Sha256;

// The all-0x01 dev private scalar, test only. A valid P-256 scalar (non-zero and far
// below the curve order), publicly known, which makes every fixture deterministic.
const DEV_KEY: [u8; 32] = [1u8; 32];

// Its public key, derived through the library rather than pinned a second time here,
// so this suite carries no constant that could drift from the firmware's.
fn dev_root_key() -> [u8; ROOT_KEY_LEN]
{
    image_signer::derive_public_key(&DEV_KEY).expect("the dev scalar is valid")
}

// Concatenates the verified payload segments so a test can compare bytes.
fn collect_payload(verified: &image_verify::VerifiedImage<'_>) -> Vec<u8>
{
    let mut out = Vec::new();
    for piece in verified.payload_segments()
    {
        out.extend_from_slice(piece);
    }
    out
}

// A unique scratch directory under the target tmp area for one test. The name
// embeds the test tag so parallel tests never collide.
fn scratch(tag: &str) -> PathBuf
{
    let mut dir = std::env::temp_dir();
    dir.push(format!("image-signer-test-{tag}-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn bin() -> Command
{
    Command::new(env!("CARGO_BIN_EXE_image-signer"))
}

fn run(args: &[&str]) -> Output
{
    bin()
        .args(args)
        .output()
        .expect("the signer binary runs")
}

// Runs the binary with `input` piped to its stdin, the way an operator would
// pipe a decrypted key (for example `gpg --decrypt ... | image-signer ...`).
fn run_with_stdin(args: &[&str], input: &[u8]) -> Output
{
    let mut child = bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the signer binary spawns");
    child
        .stdin
        .take()
        .expect("child stdin is piped")
        .write_all(input)
        .expect("write the key to child stdin");
    child
        .wait_with_output()
        .expect("the signer binary completes")
}

#[test]
fn sign_then_image_verify_accepts_under_dev_root_key()
{
    let dir = scratch("sign-ok");
    let key = dir.join("key.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");

    fs::write(&key, DEV_KEY).expect("write key");
    fs::write(&payload, b"end to end firmware payload").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        key.to_str().expect("path"),
        "--out",
        out.to_str().expect("path"),
        "--major",
        "1",
        "--minor",
        "0",
        "--revision",
        "0",
        "--build",
        "0",
        "--security-counter",
        "5",
    ]);
    assert!(output.status.success(), "sign must succeed: {output:?}");

    // The CLI output must verify under the dev root key through the same path the
    // device uses, never a separately rebuilt copy.
    let image = fs::read(&out).expect("read signed image");
    let root = image_verify::RootKey::from_bytes(dev_root_key())
        .expect("dev root on-curve");
    let segments: [&[u8]; 1] = [&image];
    let verified =
        image_verify::verify_image(&segments, &root).expect("device accepts");
    assert_eq!(collect_payload(&verified), b"end to end firmware payload");
    assert_eq!(verified.security_counter(), 5);

    let _ = fs::remove_dir_all(&dir);
}

// Lowercase hex of the 65-byte uncompressed SEC1 public key, for the
// --expect-pubkey flag.
fn hex_key(key: &[u8; ROOT_KEY_LEN]) -> String
{
    let mut s = String::with_capacity(ROOT_KEY_LEN * 2);
    for byte in key
    {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[test]
fn sign_with_a_matching_expect_pubkey_succeeds()
{
    let dir = scratch("expect-ok");
    let key = dir.join("key.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&key, DEV_KEY).expect("write key");
    fs::write(&payload, b"matching key payload").expect("write payload");

    let expected = hex_key(&dev_root_key());
    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        key.to_str().expect("path"),
        "--out",
        out.to_str().expect("path"),
        "--major",
        "1",
        "--minor",
        "0",
        "--revision",
        "0",
        "--build",
        "0",
        "--security-counter",
        "5",
        "--expect-pubkey",
        &expected,
    ]);
    assert!(output.status.success(), "matching key must sign: {output:?}");
    assert!(out.exists(), "image must be written on a matching key");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sign_with_a_mismatched_expect_pubkey_fails_closed()
{
    let dir = scratch("expect-bad");
    let key = dir.join("key.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&key, DEV_KEY).expect("write key");
    fs::write(&payload, b"wrong key payload").expect("write payload");

    // A well-formed 130-hex value that is not the dev key's public key.
    let mut other = dev_root_key();
    // Flip a coordinate byte, not the 0x04 tag, so the value stays a well-formed
    // 130-hex-char argument and the mismatch is what rejects it.
    other[1] ^= 0xFF;
    let expected = hex_key(&other);

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        key.to_str().expect("path"),
        "--out",
        out.to_str().expect("path"),
        "--major",
        "1",
        "--minor",
        "0",
        "--revision",
        "0",
        "--build",
        "0",
        "--security-counter",
        "5",
        "--expect-pubkey",
        &expected,
    ]);
    assert!(!output.status.success(), "mismatched key must fail");
    assert!(!out.exists(), "no image must be written on a key mismatch");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(
        stderr.contains("--expect-pubkey does not match"),
        "clear mismatch message: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn derive_pubkey_prints_the_dev_root_key()
{
    let dir = scratch("derive");
    let key = dir.join("key.bin");
    fs::write(&key, DEV_KEY).expect("write key");

    let output =
        run(&["derive-pubkey", "--key-file", key.to_str().expect("path")]);
    assert!(output.status.success(), "derive must succeed: {output:?}");

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    // The hex line carries the dev root key.
    let mut hex = String::new();
    for byte in dev_root_key()
    {
        hex.push_str(&format!("{byte:02x}"));
    }
    assert!(
        stdout.contains(&hex),
        "derive-pubkey must print the dev root key hex, got: {stdout}"
    );
    // The Rust array literal is present too.
    assert!(stdout.contains("pub const ROOT_KEY: [u8; 65] = ["));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_truncated_key_fails_closed()
{
    let dir = scratch("short-key");
    let key = dir.join("key.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    // 31 bytes, one short of a valid key.
    fs::write(&key, [0u8; 31]).expect("write short key");
    fs::write(&payload, b"x").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        key.to_str().expect("path"),
        "--out",
        out.to_str().expect("path"),
        "--major",
        "1",
        "--minor",
        "0",
        "--revision",
        "0",
        "--build",
        "0",
        "--security-counter",
        "0",
    ]);
    assert!(!output.status.success(), "short key must fail");
    assert!(!out.exists(), "no image must be written on a bad key");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("32 bytes"), "clear message: {stderr}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_too_long_key_fails_closed()
{
    let dir = scratch("long-key");
    let key = dir.join("key.bin");
    fs::write(&key, [0u8; 33]).expect("write long key");

    let output =
        run(&["derive-pubkey", "--key-file", key.to_str().expect("path")]);
    assert!(!output.status.success(), "long key must fail");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_key_file_fails_closed()
{
    let output =
        run(&["derive-pubkey", "--key-file", "/nonexistent/path/key.bin"]);
    assert!(!output.status.success(), "missing file must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("cannot read key file"), "clear: {stderr}");
}

#[test]
fn a_missing_required_flag_fails_closed()
{
    // No --key-file at all.
    let output = run(&["derive-pubkey"]);
    assert!(!output.status.success(), "missing flag must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("missing required flag"), "clear: {stderr}");
}

#[test]
fn a_non_numeric_version_field_fails_closed()
{
    let dir = scratch("bad-num");
    let key = dir.join("key.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&key, DEV_KEY).expect("write key");
    fs::write(&payload, b"x").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        key.to_str().expect("path"),
        "--out",
        out.to_str().expect("path"),
        "--major",
        "not-a-number",
        "--minor",
        "0",
        "--revision",
        "0",
        "--build",
        "0",
        "--security-counter",
        "0",
    ]);
    assert!(!output.status.success(), "bad number must fail");
    assert!(!out.exists(), "no image on a bad field");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_subcommand_fails_closed()
{
    let output = run(&["frobnicate"]);
    assert!(!output.status.success(), "unknown subcommand must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("unknown subcommand"), "clear: {stderr}");
}

#[test]
fn sign_reads_key_from_stdin_and_image_verify_accepts()
{
    let dir = scratch("sign-stdin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&payload, b"stdin piped firmware payload").expect("write payload");

    // The key is piped to stdin, no cleartext key file on disk.
    let output = run_with_stdin(
        &[
            "sign",
            "--payload",
            payload.to_str().expect("path"),
            "--key-file",
            "-",
            "--out",
            out.to_str().expect("path"),
            "--major",
            "1",
            "--minor",
            "0",
            "--revision",
            "0",
            "--build",
            "0",
            "--security-counter",
            "5",
        ],
        &DEV_KEY,
    );
    assert!(output.status.success(), "stdin sign must succeed: {output:?}");

    let image = fs::read(&out).expect("read signed image");
    let root = image_verify::RootKey::from_bytes(dev_root_key())
        .expect("dev root on-curve");
    let segments: [&[u8]; 1] = [&image];
    let verified =
        image_verify::verify_image(&segments, &root).expect("device accepts");
    assert_eq!(collect_payload(&verified), b"stdin piped firmware payload");
    assert_eq!(verified.security_counter(), 5);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn derive_pubkey_reads_key_from_stdin()
{
    let output = run_with_stdin(&["derive-pubkey", "--key-file", "-"], &DEV_KEY);
    assert!(output.status.success(), "stdin derive must succeed: {output:?}");

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let mut hex = String::new();
    for byte in dev_root_key()
    {
        hex.push_str(&format!("{byte:02x}"));
    }
    assert!(
        stdout.contains(&hex),
        "derive-pubkey from stdin must print the dev root key hex, got: {stdout}"
    );

    // No temp files were created, nothing to clean up.
}

#[test]
fn a_wrong_length_stdin_key_fails_closed()
{
    // 33 bytes piped in, one past a valid key. A trailing byte (such as a
    // newline) makes the length wrong, which must fail closed.
    let output = run_with_stdin(&["derive-pubkey", "--key-file", "-"], &[0u8; 33]);
    assert!(!output.status.success(), "wrong-length stdin key must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("32 bytes"), "clear message: {stderr}");
}

#[test]
fn derive_pubkey_with_an_early_closing_reader_does_not_panic()
{
    let dir = scratch("early-close");
    let key = dir.join("key.bin");
    fs::write(&key, DEV_KEY).expect("write key");

    let mut child = bin()
        .args(["derive-pubkey", "--key-file", key.to_str().expect("path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the signer binary spawns");

    // Read only the first line, then drop the reader so the read end closes
    // while the child may still be writing, the way `head -1` would.
    let first_line =
    {
        let stdout = child.stdout.take().expect("child stdout is piped");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read first line");
        line
        // reader drops here, closing the read end early.
    };

    let output = child.wait_with_output().expect("the signer binary completes");

    // The first line carries the dev root key hex.
    let mut hex = String::new();
    for byte in dev_root_key()
    {
        hex.push_str(&format!("{byte:02x}"));
    }
    assert!(
        first_line.contains(&hex),
        "first line must carry the dev root key hex, got: {first_line}"
    );

    // No panic, on either stream. A panic would print "panicked" to stderr.
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(
        !stderr.contains("panicked"),
        "the tool must not panic on an early-closing reader: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// 32 bytes are not automatically a P-256 key. An all-zero file is the scalar 0,
// which is outside [1, n-1], so the tool must refuse it rather than sign with it.
#[test]
fn an_all_zero_key_file_fails_closed()
{
    let dir = scratch("zero-key");
    let key = dir.join("key.bin");
    fs::write(&key, [0u8; 32]).expect("write zero key");

    let output =
        run(&["derive-pubkey", "--key-file", key.to_str().expect("path")]);
    assert!(!output.status.success(), "an all-zero scalar must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(
        stderr.contains("not a valid P-256 private scalar"),
        "the message must name the real cause: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

// A 32-byte file at or above the curve order is out of range too, and it must not
// silently be reduced mod n.
#[test]
fn an_out_of_range_key_file_fails_closed()
{
    let dir = scratch("high-key");
    let key = dir.join("key.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&key, [0xFFu8; 32]).expect("write out-of-range key");
    fs::write(&payload, b"x").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        key.to_str().expect("path"),
        "--out",
        out.to_str().expect("path"),
        "--major",
        "1",
        "--minor",
        "0",
        "--revision",
        "0",
        "--build",
        "0",
        "--security-counter",
        "0",
    ]);
    assert!(!output.status.success(), "an out-of-range scalar must fail");
    assert!(!out.exists(), "no image on an unusable key");

    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// assemble-bank end-to-end tests.
//
// These drive the whole subcommand through the compiled binary with raw .bin inputs.
// Raw input skips the objcopy branch (is_elf gates it), so no ARM toolchain and no
// ELF fixture is needed. The happy path proves a 256K self-verified artifact plus a
// manifest is written, the failure paths prove every rejection exits non-zero and
// writes no artifact.
// ===========================================================================

// The link origins the three firmware images are built at. They mirror the
// private constants in main.rs, which are fixed hardware addresses.
const BOOT_ORIGIN: u32 = 0x0C00_4000;
const SECURE_ORIGIN: u32 = 0x0C01_4000;
const NS_ORIGIN: u32 = 0x0802_8000;

// The fixed bring-up phrase whose SHA-256 is the bring-up private scalar. It must
// match the phrase in main.rs and crates/boot-stage/src/mock.rs. Any drift is caught
// by the tool, which refuses to build unless the derived public key equals the
// --root-key-file value.
const BRINGUP_PHRASE: &[u8] =
    b"patina_key MCU image root - BRING-UP ONLY - replace at ceremony freeze";

// Derives the bring-up root public key from the phrase, the value the tool confirms
// against --root-key-file. Derived rather than pinned, so this suite carries no
// 65-byte constant that could drift from the firmware's.
fn bringup_root_key() -> [u8; ROOT_KEY_LEN]
{
    let scalar: [u8; 32] = Sha256::digest(BRINGUP_PHRASE).into();
    image_signer::derive_public_key(&scalar).expect("the bring-up scalar is valid")
}

// Builds a minimal raw firmware .bin with a valid ARMv8-M vector table: a valid
// SRAM initial MSP, then a Thumb reset vector inside the image's own band.
fn fw_bin(origin: u32, len: usize) -> Vec<u8>
{
    let mut b = vec![0xFFu8; len];
    b[0..4].copy_from_slice(&0x2000_1000u32.to_le_bytes());
    let reset = (origin + 0x100) | 1;
    b[4..8].copy_from_slice(&reset.to_le_bytes());
    b
}

// The common flag list for an assemble-bank run over four input paths.
fn assemble_args<'a>
(
    boot: &'a str,
    secure: &'a str,
    ns: &'a str,
    root_key: &'a str,
    out: &'a str,
)
    -> Vec<&'a str>
{
    vec![
        "assemble-bank",
        "--boot",
        boot,
        "--secure",
        secure,
        "--nonsecure",
        ns,
        "--root-key-file",
        root_key,
        "--out",
        out,
        "--major",
        "0",
        "--minor",
        "0",
        "--revision",
        "1",
        "--build",
        "0",
        "--security-counter",
        "7",
    ]
}

#[test]
fn assemble_bank_happy_path_writes_a_verified_bank_and_manifest()
{
    let dir = scratch("assemble-ok");
    let boot = dir.join("boot.bin");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let root_key = dir.join("root.sec1");
    let out = dir.join("bank.bin");
    let manifest = dir.join("manifest.txt");

    fs::write(&boot, fw_bin(BOOT_ORIGIN, 0x400)).expect("write boot");
    fs::write(&secure, fw_bin(SECURE_ORIGIN, 0x400)).expect("write secure");
    fs::write(&ns, fw_bin(NS_ORIGIN, 0x400)).expect("write ns");
    fs::write(&root_key, bringup_root_key()).expect("write root key");

    let mut args = assemble_args(
        boot.to_str().expect("path"),
        secure.to_str().expect("path"),
        ns.to_str().expect("path"),
        root_key.to_str().expect("path"),
        out.to_str().expect("path"),
    );
    args.push("--manifest");
    let manifest_str = manifest.to_str().expect("path");
    args.push(manifest_str);

    let output = run(&args);
    assert!(output.status.success(), "assemble must succeed: {output:?}");

    // A full physical-bank artifact was written.
    let artifact = fs::read(&out).expect("read artifact");
    assert_eq!(artifact.len(), 262144, "the artifact is one physical bank");

    // The manifest file and the stdout copy both carry the self-verify result and the
    // inline flashing preconditions, and no longer carry the wrong single-alias /
    // TZEN=0 flashing instruction.
    let manifest_text = fs::read_to_string(&manifest).expect("read manifest");
    assert!(
        manifest_text.contains("self-verify            : PASS"),
        "manifest must report the self-verify PASS: {manifest_text}"
    );
    assert!(
        manifest_text.contains("SECBOOTADD0=0x0C004000"),
        "manifest must carry the inline flashing preconditions: {manifest_text}"
    );
    assert!(
        !manifest_text.contains("TZEN=0"),
        "manifest must not carry the wrong TZEN=0 label: {manifest_text}"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        stdout.contains("SELF-VERIFIED"),
        "stdout must carry the manifest: {stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn assemble_bank_oversize_secure_fails_closed()
{
    let dir = scratch("assemble-oversize");
    let boot = dir.join("boot.bin");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let root_key = dir.join("root.sec1");
    let out = dir.join("bank.bin");

    // One byte past the secure band. The vector table is still valid, so the
    // rejection is the size check, not a malformed image.
    fs::write(&boot, fw_bin(BOOT_ORIGIN, 0x400)).expect("write boot");
    fs::write(&secure, fw_bin(SECURE_ORIGIN, image_signer::SECURE_LEN + 1))
        .expect("write secure");
    fs::write(&ns, fw_bin(NS_ORIGIN, 0x400)).expect("write ns");
    fs::write(&root_key, bringup_root_key()).expect("write root key");

    let args = assemble_args(
        boot.to_str().expect("path"),
        secure.to_str().expect("path"),
        ns.to_str().expect("path"),
        root_key.to_str().expect("path"),
        out.to_str().expect("path"),
    );
    let output = run(&args);
    assert!(!output.status.success(), "an oversize secure image must fail");
    assert!(!out.exists(), "no artifact must be written on an oversize input");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn assemble_bank_pubkey_mismatch_fails_closed()
{
    let dir = scratch("assemble-mismatch");
    let boot = dir.join("boot.bin");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let root_key = dir.join("root.sec1");
    let out = dir.join("bank.bin");

    fs::write(&boot, fw_bin(BOOT_ORIGIN, 0x400)).expect("write boot");
    fs::write(&secure, fw_bin(SECURE_ORIGIN, 0x400)).expect("write secure");
    fs::write(&ns, fw_bin(NS_ORIGIN, 0x400)).expect("write ns");

    // A well-formed 65-byte SEC1 point that is not the bring-up key: flip a
    // coordinate byte, not the 0x04 tag, so the length stays valid and the mismatch
    // is what rejects it.
    let mut wrong = bringup_root_key();
    wrong[1] ^= 0xFF;
    fs::write(&root_key, wrong).expect("write wrong root key");

    let args = assemble_args(
        boot.to_str().expect("path"),
        secure.to_str().expect("path"),
        ns.to_str().expect("path"),
        root_key.to_str().expect("path"),
        out.to_str().expect("path"),
    );
    let output = run(&args);
    assert!(!output.status.success(), "a pubkey mismatch must fail");
    assert!(!out.exists(), "no artifact must be written on a key mismatch");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn assemble_bank_missing_input_file_fails_closed()
{
    let dir = scratch("assemble-missing");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let root_key = dir.join("root.sec1");
    let out = dir.join("bank.bin");
    let missing_boot = dir.join("does-not-exist.bin");

    fs::write(&secure, fw_bin(SECURE_ORIGIN, 0x400)).expect("write secure");
    fs::write(&ns, fw_bin(NS_ORIGIN, 0x400)).expect("write ns");
    fs::write(&root_key, bringup_root_key()).expect("write root key");

    let args = assemble_args(
        missing_boot.to_str().expect("path"),
        secure.to_str().expect("path"),
        ns.to_str().expect("path"),
        root_key.to_str().expect("path"),
        out.to_str().expect("path"),
    );
    let output = run(&args);
    assert!(!output.status.success(), "a missing input file must fail");
    assert!(!out.exists(), "no artifact must be written on a missing input");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn assemble_bank_mislinked_ns_reset_vector_fails_closed()
{
    let dir = scratch("assemble-mislinked");
    let boot = dir.join("boot.bin");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let root_key = dir.join("root.sec1");
    let out = dir.join("bank.bin");

    fs::write(&boot, fw_bin(BOOT_ORIGIN, 0x400)).expect("write boot");
    fs::write(&secure, fw_bin(SECURE_ORIGIN, 0x400)).expect("write secure");

    // A mislinked NS image: zero the reset vector so it is not a Thumb address
    // inside the NS band. This is the wrong-objcopy-base / wrong-origin class the
    // packaging tool exists to catch before any byte lands in the bank.
    let mut bad_ns = fw_bin(NS_ORIGIN, 0x400);
    bad_ns[4..8].copy_from_slice(&0u32.to_le_bytes());
    fs::write(&ns, bad_ns).expect("write mislinked ns");
    fs::write(&root_key, bringup_root_key()).expect("write root key");

    let args = assemble_args(
        boot.to_str().expect("path"),
        secure.to_str().expect("path"),
        ns.to_str().expect("path"),
        root_key.to_str().expect("path"),
        out.to_str().expect("path"),
    );
    let output = run(&args);
    assert!(!output.status.success(), "a mislinked NS image must fail");
    assert!(!out.exists(), "no artifact must be written on a mislinked NS image");

    let _ = fs::remove_dir_all(&dir);
}

// ===========================================================================
// External-signature flow CLI tests (prepare-external / finalize-external).
//
// They drive the whole two-step flow through the compiled binary with raw .bin
// inputs (raw input skips objcopy). A software P-256 key stands in for the YubiKey:
// the test signs the digest the binary emits, then hands the signature back to
// finalize-external. This proves the offline round trip end to end without any
// private key ever reaching the tool.
// ===========================================================================

// Signs a 32-byte digest as a RAW ECDSA P-256 signature (prehash, no re-hash).
fn ecdsa_sign_digest(digest: &[u8], key: &[u8; 32]) -> p256::ecdsa::Signature
{
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let sk = SigningKey::from_slice(key).expect("the dev scalar is valid");
    sk.sign_prehash(digest).expect("sign the digest")
}

// The low-s twin of a signature as raw 64 bytes.
fn low_s_raw(sig: &p256::ecdsa::Signature) -> Vec<u8>
{
    let low = sig.normalize_s();
    low.to_bytes().to_vec()
}

// The high-s twin (n - s) of a signature as raw 64 bytes.
fn high_s_raw(sig: &p256::ecdsa::Signature) -> Vec<u8>
{
    let low = sig.normalize_s();
    let (r, s) = low.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r, -s).expect("n - s is valid");
    high.to_bytes().to_vec()
}

// The ASN.1 DER encoding of the low-s twin, what openssl / PIV emit by default.
fn low_s_der(sig: &p256::ecdsa::Signature) -> Vec<u8>
{
    sig.normalize_s().to_der().as_bytes().to_vec()
}

// Runs prepare-external over three raw .bin paths and returns the digest and
// context paths. Asserts the binary succeeded and printed the operator note.
fn run_prepare(dir: &std::path::Path) -> (PathBuf, PathBuf)
{
    let boot = dir.join("boot.bin");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let digest = dir.join("digest.bin");
    let context = dir.join("context.bin");

    fs::write(&boot, fw_bin(BOOT_ORIGIN, 0x400)).expect("write boot");
    fs::write(&secure, fw_bin(SECURE_ORIGIN, 0x400)).expect("write secure");
    fs::write(&ns, fw_bin(NS_ORIGIN, 0x400)).expect("write ns");

    let output = run(&[
        "prepare-external",
        "--boot",
        boot.to_str().expect("path"),
        "--secure",
        secure.to_str().expect("path"),
        "--nonsecure",
        ns.to_str().expect("path"),
        "--digest",
        digest.to_str().expect("path"),
        "--context",
        context.to_str().expect("path"),
        "--major",
        "0",
        "--minor",
        "0",
        "--revision",
        "1",
        "--build",
        "0",
        "--security-counter",
        "7",
    ]);
    assert!(output.status.success(), "prepare must succeed: {output:?}");

    // The digest is 32 raw bytes, and the note tells the operator to sign it raw
    // without re-hashing.
    let digest_bytes = fs::read(&digest).expect("read digest");
    assert_eq!(digest_bytes.len(), 32, "the digest is a 32-byte SHA-256 output");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        stdout.contains("RAW ECDSA P-256 signature") && stdout.contains("NOT re-hash"),
        "the operator note must say sign raw, no re-hash: {stdout}"
    );

    (digest, context)
}

// Runs finalize-external and returns the raw Output plus the bank path.
fn run_finalize
(
    dir: &std::path::Path,
    context: &std::path::Path,
    sig_path: &std::path::Path,
    pubkey: &[u8; ROOT_KEY_LEN],
    sig_format: Option<&str>,
)
    -> (Output, PathBuf)
{
    let pubkey_path = dir.join("pubkey.sec1");
    let out = dir.join("bank.bin");
    let manifest = dir.join("manifest.txt");
    fs::write(&pubkey_path, pubkey).expect("write pubkey");

    let mut args = vec![
        String::from("finalize-external"),
        String::from("--context"),
        context.to_str().expect("path").to_string(),
        String::from("--signature"),
        sig_path.to_str().expect("path").to_string(),
        String::from("--pubkey"),
        pubkey_path.to_str().expect("path").to_string(),
        String::from("--out"),
        out.to_str().expect("path").to_string(),
        String::from("--manifest"),
        manifest.to_str().expect("path").to_string(),
    ];
    if let Some(fmt) = sig_format
    {
        args.push(String::from("--sig-format"));
        args.push(fmt.to_string());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    (run(&refs), out)
}

#[test]
fn external_flow_low_s_round_trip_writes_a_verified_bank()
{
    let dir = scratch("ext-low-s");
    let (digest_path, context_path) = run_prepare(&dir);

    // The operator signs the digest offline.
    let digest = fs::read(&digest_path).expect("read digest");
    let sig = ecdsa_sign_digest(&digest, &DEV_KEY);
    let sig_path = dir.join("sig.raw");
    fs::write(&sig_path, low_s_raw(&sig)).expect("write signature");

    let (output, out) =
        run_finalize(&dir, &context_path, &sig_path, &dev_root_key(), None);
    assert!(output.status.success(), "finalize must succeed: {output:?}");

    let bank = fs::read(&out).expect("read bank");
    assert_eq!(bank.len(), 262144, "the artifact is one physical bank");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        stdout.contains("self-verify            : PASS"),
        "the manifest must report the self-verify PASS: {stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn external_flow_high_s_is_normalized_into_a_verified_bank()
{
    let dir = scratch("ext-high-s");
    let (digest_path, context_path) = run_prepare(&dir);

    let digest = fs::read(&digest_path).expect("read digest");
    let sig = ecdsa_sign_digest(&digest, &DEV_KEY);
    // Deliberately hand finalize the high-s encoding the device would reject.
    let sig_path = dir.join("sig.raw");
    fs::write(&sig_path, high_s_raw(&sig)).expect("write high-s signature");

    let (output, out) =
        run_finalize(&dir, &context_path, &sig_path, &dev_root_key(), None);
    assert!(
        output.status.success(),
        "finalize must normalize a high-s signature: {output:?}"
    );
    assert_eq!(fs::read(&out).expect("read bank").len(), 262144);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn external_flow_accepts_a_der_signature()
{
    let dir = scratch("ext-der");
    let (digest_path, context_path) = run_prepare(&dir);

    let digest = fs::read(&digest_path).expect("read digest");
    let sig = ecdsa_sign_digest(&digest, &DEV_KEY);
    // openssl / PIV emit DER by default. Auto-detect must accept it.
    let sig_path = dir.join("sig.der");
    fs::write(&sig_path, low_s_der(&sig)).expect("write DER signature");

    let (output, out) =
        run_finalize(&dir, &context_path, &sig_path, &dev_root_key(), None);
    assert!(output.status.success(), "finalize must accept DER: {output:?}");
    assert_eq!(fs::read(&out).expect("read bank").len(), 262144);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn external_flow_rejects_a_wrong_key_signature_and_writes_no_bank()
{
    let dir = scratch("ext-wrong-key");
    let (digest_path, context_path) = run_prepare(&dir);

    // Sign the correct digest with a different key, but pin the dev key. The
    // signature is well-formed, so only the verify inside finalize catches it.
    let digest = fs::read(&digest_path).expect("read digest");
    let wrong = ecdsa_sign_digest(&digest, &[9u8; 32]);
    let sig_path = dir.join("sig.raw");
    fs::write(&sig_path, low_s_raw(&wrong)).expect("write signature");

    let (output, out) =
        run_finalize(&dir, &context_path, &sig_path, &dev_root_key(), None);
    assert!(!output.status.success(), "a wrong-key signature must fail");
    assert!(!out.exists(), "no bank must be written on a rejected signature");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(
        stderr.contains("does not verify"),
        "the message must name the verify failure: {stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn external_flow_rejects_a_corrupt_signature_and_writes_no_bank()
{
    let dir = scratch("ext-corrupt-sig");
    let (digest_path, context_path) = run_prepare(&dir);

    let digest = fs::read(&digest_path).expect("read digest");
    let sig = ecdsa_sign_digest(&digest, &DEV_KEY);
    let mut raw = low_s_raw(&sig);
    // Truncate the signature so it parses as neither raw nor DER.
    raw.truncate(50);
    let sig_path = dir.join("sig.raw");
    fs::write(&sig_path, &raw).expect("write corrupt signature");

    let (output, out) = run_finalize(
        &dir,
        &context_path,
        &sig_path,
        &dev_root_key(),
        Some("raw"),
    );
    assert!(!output.status.success(), "a corrupt signature must fail");
    assert!(!out.exists(), "no bank must be written on a corrupt signature");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn external_flow_signature_over_a_different_digest_is_rejected()
{
    let dir = scratch("ext-wrong-digest");
    let (_digest_path, context_path) = run_prepare(&dir);

    // A signature over some other message, valid under the dev key, must be rejected:
    // the verify recomputes the digest from the context.
    let other_digest = Sha256::digest(b"a totally different message");
    let sig = ecdsa_sign_digest(&other_digest, &DEV_KEY);
    let sig_path = dir.join("sig.raw");
    fs::write(&sig_path, low_s_raw(&sig)).expect("write signature");

    let (output, out) =
        run_finalize(&dir, &context_path, &sig_path, &dev_root_key(), None);
    assert!(!output.status.success(), "a wrong-digest signature must fail");
    assert!(!out.exists(), "no bank on a signature over a different digest");

    let _ = fs::remove_dir_all(&dir);
}

// The external finalize bank is byte-identical to the assemble-bank output for the
// same inputs and key. This cross-checks that the external and internal paths lay
// down the exact same bytes.
#[test]
fn external_flow_bank_matches_assemble_bank_byte_for_byte()
{
    let dir = scratch("ext-vs-internal");

    // Build the external bank. prepare-external signs nothing, so the key used to sign
    // the digest is the only key in play, and it must equal the pinned key. Use the
    // bring-up key so assemble-bank (which signs with the bring-up key) produces the
    // comparison bank under the same key.
    let boot = dir.join("boot.bin");
    let secure = dir.join("secure.bin");
    let ns = dir.join("ns.bin");
    let digest_path = dir.join("digest.bin");
    let context_path = dir.join("context.bin");
    fs::write(&boot, fw_bin(BOOT_ORIGIN, 0x400)).expect("write boot");
    fs::write(&secure, fw_bin(SECURE_ORIGIN, 0x400)).expect("write secure");
    fs::write(&ns, fw_bin(NS_ORIGIN, 0x400)).expect("write ns");

    let prep = run(&[
        "prepare-external",
        "--boot",
        boot.to_str().expect("path"),
        "--secure",
        secure.to_str().expect("path"),
        "--nonsecure",
        ns.to_str().expect("path"),
        "--digest",
        digest_path.to_str().expect("path"),
        "--context",
        context_path.to_str().expect("path"),
        "--major",
        "0",
        "--minor",
        "0",
        "--revision",
        "1",
        "--build",
        "0",
        "--security-counter",
        "7",
    ]);
    assert!(prep.status.success(), "prepare must succeed: {prep:?}");

    // Sign the digest with the bring-up key (SHA-256 of the phrase), the same key
    // assemble-bank uses, deterministically (RFC 6979), so the low-s signature is the
    // same.
    let bringup_scalar: [u8; 32] = Sha256::digest(BRINGUP_PHRASE).into();
    let digest = fs::read(&digest_path).expect("read digest");
    let sig = ecdsa_sign_digest(&digest, &bringup_scalar);
    let sig_path = dir.join("sig.raw");
    fs::write(&sig_path, low_s_raw(&sig)).expect("write signature");

    let (output, external_out) =
        run_finalize(&dir, &context_path, &sig_path, &bringup_root_key(), None);
    assert!(output.status.success(), "finalize must succeed: {output:?}");

    // Build the assemble-bank comparison artifact from the same raw inputs.
    let root_key = dir.join("root.sec1");
    let internal_out = dir.join("internal-bank.bin");
    fs::write(&root_key, bringup_root_key()).expect("write root key");
    let assemble = run(&assemble_args(
        boot.to_str().expect("path"),
        secure.to_str().expect("path"),
        ns.to_str().expect("path"),
        root_key.to_str().expect("path"),
        internal_out.to_str().expect("path"),
    ));
    assert!(assemble.status.success(), "assemble must succeed: {assemble:?}");

    let external_bank = fs::read(&external_out).expect("read external bank");
    let internal_bank = fs::read(&internal_out).expect("read internal bank");
    assert_eq!(
        external_bank, internal_bank,
        "the external and internal paths must produce identical banks"
    );

    let _ = fs::remove_dir_all(&dir);
}
