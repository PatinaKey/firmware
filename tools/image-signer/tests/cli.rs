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

// The all-0x01 dev seed and its pinned public key, used to prove the CLI
// produces an image the firmware's dev root key accepts.
const DEV_SEED: [u8; 32] = [1u8; 32];
const DEV_ROOT_KEY: [u8; 32] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95,
    0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b,
    0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

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
// pipe a decrypted seed (for example `gpg --decrypt ... | image-signer ...`).
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
        .expect("write seed to child stdin");
    child
        .wait_with_output()
        .expect("the signer binary completes")
}

#[test]
fn sign_then_image_verify_accepts_under_dev_root_key()
{
    let dir = scratch("sign-ok");
    let seed = dir.join("seed.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");

    fs::write(&seed, DEV_SEED).expect("write seed");
    fs::write(&payload, b"end to end firmware payload").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        seed.to_str().expect("path"),
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

    // The CLI output must verify under the dev root key through the SAME path
    // the device uses, never a separately rebuilt copy.
    let image = fs::read(&out).expect("read signed image");
    let root = image_verify::RootKey::from_bytes(DEV_ROOT_KEY)
        .expect("dev root on-curve");
    let verified =
        image_verify::verify_image(&image, &root).expect("device accepts");
    assert_eq!(verified.payload(), b"end to end firmware payload");
    assert_eq!(verified.security_counter(), 5);

    let _ = fs::remove_dir_all(&dir);
}

// Lowercase hex of a 32-byte key, for the --expect-pubkey flag.
fn hex32(key: &[u8; 32]) -> String
{
    let mut s = String::with_capacity(64);
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
    let seed = dir.join("seed.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&seed, DEV_SEED).expect("write seed");
    fs::write(&payload, b"matching key payload").expect("write payload");

    let expected = hex32(&DEV_ROOT_KEY);
    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        seed.to_str().expect("path"),
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
    let seed = dir.join("seed.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&seed, DEV_SEED).expect("write seed");
    fs::write(&payload, b"wrong key payload").expect("write payload");

    // A valid 64-hex value that is NOT the dev seed's public key (all zeros is
    // off-curve, so use the dev key with its first byte flipped, still 64 hex).
    let mut other = DEV_ROOT_KEY;
    other[0] ^= 0xFF;
    let expected = hex32(&other);

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        seed.to_str().expect("path"),
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
    let seed = dir.join("seed.bin");
    fs::write(&seed, DEV_SEED).expect("write seed");

    let output =
        run(&["derive-pubkey", "--key-file", seed.to_str().expect("path")]);
    assert!(output.status.success(), "derive must succeed: {output:?}");

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    // The hex line carries the dev root key.
    let mut hex = String::new();
    for byte in DEV_ROOT_KEY
    {
        hex.push_str(&format!("{byte:02x}"));
    }
    assert!(
        stdout.contains(&hex),
        "derive-pubkey must print the dev root key hex, got: {stdout}"
    );
    // The Rust array literal is present too.
    assert!(stdout.contains("pub const ROOT_KEY: [u8; 32] = ["));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_truncated_seed_fails_closed()
{
    let dir = scratch("short-seed");
    let seed = dir.join("seed.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    // 31 bytes, one short of a valid seed.
    fs::write(&seed, [0u8; 31]).expect("write short seed");
    fs::write(&payload, b"x").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        seed.to_str().expect("path"),
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
    assert!(!output.status.success(), "short seed must fail");
    assert!(!out.exists(), "no image must be written on a bad seed");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("32 bytes"), "clear message: {stderr}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_too_long_seed_fails_closed()
{
    let dir = scratch("long-seed");
    let seed = dir.join("seed.bin");
    fs::write(&seed, [0u8; 33]).expect("write long seed");

    let output =
        run(&["derive-pubkey", "--key-file", seed.to_str().expect("path")]);
    assert!(!output.status.success(), "long seed must fail");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_seed_file_fails_closed()
{
    let output =
        run(&["derive-pubkey", "--key-file", "/nonexistent/path/seed.bin"]);
    assert!(!output.status.success(), "missing file must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("cannot read seed file"), "clear: {stderr}");
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
    let seed = dir.join("seed.bin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&seed, DEV_SEED).expect("write seed");
    fs::write(&payload, b"x").expect("write payload");

    let output = run(&[
        "sign",
        "--payload",
        payload.to_str().expect("path"),
        "--key-file",
        seed.to_str().expect("path"),
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
fn sign_reads_seed_from_stdin_and_image_verify_accepts()
{
    let dir = scratch("sign-stdin");
    let payload = dir.join("fw.bin");
    let out = dir.join("image.signed");
    fs::write(&payload, b"stdin piped firmware payload").expect("write payload");

    // The seed is piped to stdin, no cleartext seed file on disk.
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
        &DEV_SEED,
    );
    assert!(output.status.success(), "stdin sign must succeed: {output:?}");

    let image = fs::read(&out).expect("read signed image");
    let root = image_verify::RootKey::from_bytes(DEV_ROOT_KEY)
        .expect("dev root on-curve");
    let verified =
        image_verify::verify_image(&image, &root).expect("device accepts");
    assert_eq!(verified.payload(), b"stdin piped firmware payload");
    assert_eq!(verified.security_counter(), 5);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn derive_pubkey_reads_seed_from_stdin()
{
    let output = run_with_stdin(&["derive-pubkey", "--key-file", "-"], &DEV_SEED);
    assert!(output.status.success(), "stdin derive must succeed: {output:?}");

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let mut hex = String::new();
    for byte in DEV_ROOT_KEY
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
fn a_wrong_length_stdin_seed_fails_closed()
{
    // 33 bytes piped in, one past a valid seed. A trailing byte (such as a
    // newline) makes the length wrong, which must fail closed.
    let output = run_with_stdin(&["derive-pubkey", "--key-file", "-"], &[0u8; 33]);
    assert!(!output.status.success(), "wrong-length stdin seed must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf8");
    assert!(stderr.contains("32 bytes"), "clear message: {stderr}");
}

#[test]
fn derive_pubkey_with_an_early_closing_reader_does_not_panic()
{
    let dir = scratch("early-close");
    let seed = dir.join("seed.bin");
    fs::write(&seed, DEV_SEED).expect("write seed");

    let mut child = bin()
        .args(["derive-pubkey", "--key-file", seed.to_str().expect("path")])
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
        // reader drops HERE, closing the read end early.
    };

    let output = child.wait_with_output().expect("the signer binary completes");

    // The first line carries the dev root key hex.
    let mut hex = String::new();
    for byte in DEV_ROOT_KEY
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
