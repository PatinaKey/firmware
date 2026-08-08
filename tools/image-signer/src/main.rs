//! Command-line front end for the patina_key firmware-image signer.
//!
//! Two subcommands:
//!
//! - `sign`: signs a firmware binary into a complete signed image.
//! - `derive-pubkey`: prints the public key for a private key, so the operator
//!   can pin it into the firmware.
//!
//! Both subcommands take the 32-byte ECDSA P-256 private key through
//! `--key-file <PATH>`. The value is either a filesystem path or the single
//! character `-`, which reads the key from stdin. The stdin form lets a decrypted
//! key be piped in (for example from `gpg --decrypt`). The tool never accepts the
//! key bytes as a literal argument, so the key cannot leak through a process listing
//! or shell history.
//!
//! The 32 bytes are the big-endian private scalar `d`, which must lie in `[1, n-1]`.
//! An all-zero file, or any value at or above the curve order, is not a key and is
//! rejected.
//!
//! Arguments are parsed by hand over `std::env::args`. Every bad input fails closed:
//! a clear message to stderr and a non-zero exit.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::hash::BuildHasher;
use std::hash::Hasher;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use image_signer::BOOT_OFFSET;
use image_signer::DESCRIPTOR_OFFSET;
use image_signer::DIGEST_LEN;
use image_signer::ImageSigner;
use image_signer::NS_LEN;
use image_signer::NS_OFFSET;
use image_signer::SECURE_LEN;
use image_signer::SECURE_OFFSET;
use image_signer::SigFormat;
use image_signer::SoftwareSigner;
use image_signer::assemble_bank;
use image_signer::build_signed_image;
use image_signer::finalize_external;
use image_signer::parse_signature;
use image_signer::prepare_external;
use image_verify::ImageVersion;
use image_verify::ROOT_KEY_LEN;
use sha2::Digest;
use sha2::Sha256;
use zeroize::Zeroizing;

// The number of private-key bytes the tool accepts. A P-256 private scalar is
// exactly this many bytes, big-endian.
const KEY_LEN: usize = 32;

// The bring-up phrase whose SHA-256 is the bring-up private scalar. This must match
// crates/boot-stage/src/mock.rs BRINGUP_PHRASE. Any drift is caught by
// assemble_bank, which refuses to build unless the derived public key equals the
// pinned root key file, so a stale phrase cannot produce a wrong image.
const BRINGUP_PHRASE: &[u8] =
    b"patina_key MCU image root - BRING-UP ONLY - replace at ceremony freeze";

// The link origins the three firmware images are built at. A loaded region whose
// vector table does not sit at its origin means a mislinked ELF or a wrong
// objcopy base, which assemble-bank refuses.
const BOOT_ORIGIN: u32 = 0x0C00_4000;
const SECURE_ORIGIN: u32 = 0x0C01_4000;
const NS_ORIGIN: u32 = 0x0802_8000;

// The two alias views of the physical bank base. Flashing the combined image at
// either address programs the same physical cells.
const BANK_BASE_SECURE: u32 = 0x0C00_0000;
const BANK_BASE_NS: u32 = 0x0800_0000;

// The lowest and highest valid initial-MSP values: anywhere in the contiguous
// on-chip SRAM. RM0456 memory map (STM32U545): SRAM1+SRAM2+SRAM3+SRAM4 total
// 256 KB (0x40000) from base 0x2000_0000, so the top is 0x2004_0000. This is a
// bench-tool sanity bound on the reset MSP, not a security boundary.
const SRAM_LOW: u32 = 0x2000_0000;
const SRAM_HIGH: u32 = 0x2004_0000;

// The number of hex chars an uncompressed SEC1 public key prints as: two per byte
// over the 65-byte point.
const PUBKEY_HEX_LEN: usize = ROOT_KEY_LEN * 2;

// A clear error string carried up to the top-level handler, which prints it to
// stderr and exits non-zero.
type ToolError = String;

// The classified result of a stdout write, decided without touching any I/O so the
// decision is unit-testable on synthetic errors.
//
// - Done: the write succeeded.
// - ReaderClosed: a broken pipe, the downstream consumer (such as `head`) closed
//   the read end. That is a normal, successful end of a pipeline, not a failure.
// - Failed: any other write error, a real problem to surface to stderr.
enum WriteOutcome
{
    Done,
    ReaderClosed,
    Failed(ToolError),
}

// Classifies a write result into a WriteOutcome. Pure: no I/O, no exit, so it can
// be tested deterministically with a synthetic io::Error.
fn classify_write(result: std::io::Result<()>) -> WriteOutcome
{
    match result
    {
        Ok(()) => WriteOutcome::Done,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            WriteOutcome::ReaderClosed
        }
        Err(e) => WriteOutcome::Failed(format!("cannot write to stdout: {e}")),
    }
}

// Writes a finished block of text to stdout, tolerant of a closed reader.
//
// The write result is classified by classify_write, then acted on: a success
// returns Ok, a broken pipe exits cleanly with code 0 rather than panicking the
// way `println!` does, any other error surfaces as a ToolError that main prints
// to stderr with a non-zero exit.
//
// Callers must drop every secret (the seed, the signer) before calling this. A
// broken pipe exits through `process::exit`, which skips destructors, so nothing
// secret may still be live at this point. The public key passed in here is not
// secret.
fn write_stdout(text: &str) -> Result<(), ToolError>
{
    let mut out = std::io::stdout();
    let result = out.write_all(text.as_bytes()).and_then(|()| out.flush());
    match classify_write(result)
    {
        WriteOutcome::Done => Ok(()),
        WriteOutcome::ReaderClosed =>
        {
            // The reader closed its end because it already received the output it
            // wanted, so exit quietly and successfully.
            std::process::exit(0);
        }
        WriteOutcome::Failed(message) => Err(message),
    }
}

fn main() -> ExitCode
{
    let args: Vec<String> = env::args().collect();
    match run(&args)
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) =>
        {
            eprintln!("image-signer: {message}");
            ExitCode::FAILURE
        }
    }
}

// Dispatches on the subcommand.
fn run(args: &[String]) -> Result<(), ToolError>
{
    let command = args.get(1).map(String::as_str);
    match command
    {
        Some("sign") => run_sign(&args[2..]),
        Some("derive-pubkey") => run_derive_pubkey(&args[2..]),
        Some("assemble-bank") => run_assemble_bank(&args[2..]),
        Some("prepare-external") => run_prepare_external(&args[2..]),
        Some("finalize-external") => run_finalize_external(&args[2..]),
        Some("--help") | Some("-h") | None => print_usage(),
        Some(other) => Err(format!(
            "unknown subcommand '{other}', expected 'sign', 'derive-pubkey', \
              'assemble-bank', 'prepare-external', or 'finalize-external'"
        )),
    }
}

// An explicit help request prints usage to stdout so it can be piped. The error
// path for bad args never calls this: it returns an Err that main prints to stderr
// with a non-zero exit.
fn print_usage() -> Result<(), ToolError>
{
    let usage = "\
patina_key firmware-image signer (ECDSA P-256 over SHA-256)

USAGE:
  image-signer sign --payload <FILE> --key-file <PATH> --out <FILE> \\
    --major <N> --minor <N> --revision <N> --build <N> \\
    --security-counter <N> [--expect-pubkey <HEX>]

  image-signer derive-pubkey --key-file <PATH>

  image-signer assemble-bank --boot <FILE> --secure <FILE> \\
    --nonsecure <FILE> --root-key-file <FILE> --out <FILE> \\
    --major <N> --minor <N> --revision <N> --build <N> \\
    --security-counter <N> [--manifest <FILE>]

  image-signer prepare-external --boot <FILE> --secure <FILE> \\
    --nonsecure <FILE> --digest <FILE> --context <FILE> \\
    --major <N> --minor <N> --revision <N> --build <N> \\
    --security-counter <N> [--digest-hex <FILE>]

  image-signer finalize-external --context <FILE> --signature <FILE> \\
    --pubkey <FILE> --out <FILE> [--sig-format raw|der|auto] \\
    [--manifest <FILE>]

  --key-file takes a path to a 32-byte P-256 private key, or '-' to read
  it from stdin (for example: gpg --decrypt key.gpg | image-signer ... \\
  --key-file -). The key is never passed as a literal argument.

  --expect-pubkey takes 130 hex chars, the 65-byte uncompressed SEC1
  public key.

  assemble-bank is the BRING-UP path. It builds one flashable STM32U545
  A/B bank image from the three firmware images (ELF or raw .bin), signing
  with the bring-up key (SHA-256 of the fixed bring-up phrase). It confirms
  the public key equals --root-key-file (pass the BRING-UP key file, the
  bring-up phrase's public key) and self-verifies the assembled bank the
  way the device does. The PRODUCTION trust anchor
  (crates/boot-stage/product_root_key.sec1) is a DIFFERENT key, so use the
  finalize-external path below to build a production bank.

  prepare-external / finalize-external split assembly around an OFFLINE
  signature, so the private key NEVER touches this tool. prepare-external
  writes --digest (32 raw bytes, SHA-256 of HEADER||PAYLOAD) and --context
  (a self-describing blob). The operator signs the DIGEST as a RAW ECDSA
  P-256 signature over the 32-byte hash (the card signs the hash, it must
  NOT re-hash), for example a YubiKey PIV slot with touch plus PIN.
  finalize-external ingests --context, the external --signature (raw 64-byte
  r||s or ASN.1 DER, auto-detected or forced by --sig-format), and the
  pinned --pubkey (65-byte SEC1, the production trust anchor
  crates/boot-stage/product_root_key.sec1). It normalizes the signature to low-s,
  verifies it against --pubkey, lays out the bank, and self-verifies. A
  signature that does not verify writes no artifact.

Every input is validated. A bad input exits non-zero.
";
    write_stdout(usage)
}

// Pulls the value following a flag out of the argument list. Returns an error if
// the flag is missing or has no value.
fn take_value<'a>
(
    args: &'a [String],
    flag: &str,
)
    -> Result<&'a str, ToolError>
{
    let mut iter = args.iter();
    while let Some(arg) = iter.next()
    {
        if arg == flag
        {
            return iter
                .next()
                .map(String::as_str)
                .ok_or_else(|| format!("flag '{flag}' needs a value"));
        }
    }
    Err(format!("missing required flag '{flag}'"))
}

// Pulls the value of an OPTIONAL flag out of the argument list.
//
// Three outcomes, kept distinct so a present-but-valueless flag is never
// silently treated as absent:
//
// - Ok(None): the flag is not present at all.
// - Ok(Some(value)): the flag is present and carries a value.
// - Err: the flag is present but has no following value, a user error.
fn take_optional_value<'a>
(
    args: &'a [String],
    flag: &str,
)
    -> Result<Option<&'a str>, ToolError>
{
    let mut iter = args.iter();
    while let Some(arg) = iter.next()
    {
        if arg == flag
        {
            return iter
                .next()
                .map(String::as_str)
                .map(Some)
                .ok_or_else(|| format!("flag '{flag}' needs a value"));
        }
    }
    Ok(None)
}

// Parses an unsigned integer flag of the requested width through a common path.
fn parse_u8(args: &[String], flag: &str) -> Result<u8, ToolError>
{
    take_value(args, flag)?
        .parse::<u8>()
        .map_err(|_| format!("flag '{flag}' must be a number in 0..=255"))
}

fn parse_u16(args: &[String], flag: &str) -> Result<u16, ToolError>
{
    take_value(args, flag)?
        .parse::<u16>()
        .map_err(|_| format!("flag '{flag}' must be a number in 0..=65535"))
}

fn parse_u32(args: &[String], flag: &str) -> Result<u32, ToolError>
{
    take_value(args, flag)?
        .parse::<u32>()
        .map_err(|_| format!("flag '{flag}' must be a 32-bit number"))
}

// Appends `bytes` to `out` as contiguous lowercase hex, two chars per byte.
fn push_hex(out: &mut String, bytes: &[u8])
{
    for byte in bytes
    {
        out.push_str(&format!("{byte:02x}"));
    }
}

// Parses a single lowercase-or-uppercase hex nibble into 0..=15.
fn hex_nibble(c: u8) -> Option<u8>
{
    match c
    {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// Parses exactly 130 hex chars into a 65-byte uncompressed SEC1 public key. Fails
// closed on a wrong length or any non-hex char, and never panics.
fn parse_pubkey_hex(hex: &str) -> Result<[u8; ROOT_KEY_LEN], ToolError>
{
    let bytes = hex.as_bytes();
    if bytes.len() != PUBKEY_HEX_LEN
    {
        return Err(format!(
            "--expect-pubkey must be {PUBKEY_HEX_LEN} hex chars \
             ({ROOT_KEY_LEN} bytes, uncompressed SEC1), got {} chars",
            bytes.len()
        ));
    }
    let mut out = [0u8; ROOT_KEY_LEN];
    for (i, slot) in out.iter_mut().enumerate()
    {
        let hi = bytes
            .get(i * 2)
            .and_then(|c| hex_nibble(*c))
            .ok_or_else(|| String::from("--expect-pubkey has a non-hex char"))?;
        let lo = bytes
            .get(i * 2 + 1)
            .and_then(|c| hex_nibble(*c))
            .ok_or_else(|| String::from("--expect-pubkey has a non-hex char"))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

// Loads the private key named by the `--key-file` value and validates it is exactly
// 32 bytes. The value is either `-`, which reads the raw key from stdin, or a
// filesystem path. Whether those 32 bytes are a valid scalar is decided by
// SoftwareSigner, which fails closed on a zero or out-of-range value.
fn load_key(key_file: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, ToolError>
{
    // For stdin, label the source "stdin" so a wrong-length error names the real
    // origin rather than the literal '-'. For a path, the path is the label.
    let (raw, source) = if key_file == "-"
    {
        (read_stdin_bytes()?, "stdin")
    }
    else
    {
        let bytes = Zeroizing::new
        (
            fs::read(key_file)
                .map_err(|e| format!("cannot read key file '{key_file}': {e}"))?,
        );
        (bytes, key_file)
    };
    key_from_bytes(&raw, source)
}

// Reads stdin to end into a Zeroizing buffer. The decrypted key can be piped in
// with no cleartext file on disk. The bytes are wiped when the buffer drops.
fn read_stdin_bytes() -> Result<Zeroizing<Vec<u8>>, ToolError>
{
    // Pre-size to KEY_LEN + 1 so a 32-byte key needs no growth (no key copy left
    // in a freed allocation), while the +1 still lets an over-long input be read
    // and rejected by the length check.
    let mut buffer = Zeroizing::new(Vec::with_capacity(KEY_LEN + 1));
    std::io::stdin()
        .read_to_end(&mut buffer)
        .map_err(|e| format!("cannot read key from stdin: {e}"))?;
    Ok(buffer)
}

// Validates raw key bytes are exactly 32 long and copies them into a fixed Zeroizing
// array. A trailing newline or any extra byte makes the length wrong, so it fails
// closed. The `source` label names the origin so the error message points the
// operator at the right input.
fn key_from_bytes
(
    raw: &[u8],
    source: &str,
)
    -> Result<Zeroizing<[u8; KEY_LEN]>, ToolError>
{
    let got = raw.len();
    let arr: [u8; KEY_LEN] = raw.try_into().map_err(|_| format!(
        "key from '{source}' must be exactly {KEY_LEN} bytes, got {got}"
    ))?;
    Ok(Zeroizing::new(arr))
}

fn run_sign(args: &[String]) -> Result<(), ToolError>
{
    let payload_path = take_value(args, "--payload")?;
    let key_file = take_value(args, "--key-file")?;
    let out_path = take_value(args, "--out")?;

    let version = ImageVersion
    {
        major: parse_u8(args, "--major")?,
        minor: parse_u8(args, "--minor")?,
        revision: parse_u16(args, "--revision")?,
        build: parse_u32(args, "--build")?,
    };
    let security_counter = parse_u32(args, "--security-counter")?;

    let payload = fs::read(payload_path)
        .map_err(|e| format!("cannot read payload file '{payload_path}': {e}"))?;
    let key = load_key(key_file)?;

    // A 32-byte file is not automatically a key: the scalar must lie in [1, n-1].
    // This fails closed on an all-zero or out-of-range value.
    let signer = SoftwareSigner::from_key(&key)
        .map_err(|e| format!("the key from '{key_file}' is unusable: {e}"))?;

    // Optional guard against signing with the wrong key file. If the operator
    // supplies an expected public key, it must equal the key the signer reports
    // before any image is written, else the tool fails closed.
    if let Some(expected_hex) = take_optional_value(args, "--expect-pubkey")?
    {
        let expected = parse_pubkey_hex(expected_hex)?;
        if expected != signer.public_key()
        {
            return Err(String::from(
                "--expect-pubkey does not match the key's public key, \
                 refusing to sign with the wrong key"
            ));
        }
    }

    let image = build_signed_image(&payload, version, security_counter, &signer)
        .map_err(|e| format!("signing failed: {e}"))?;

    fs::write(out_path, &image)
        .map_err(|e| format!("cannot write output file '{out_path}': {e}"))?;

    // Informational status line on stderr. The image is already written, so this
    // line must never decide the outcome. A broken stderr pipe is swallowed rather
    // than exiting the process, because the key and signer are still live here and
    // their destructors must run to wipe the plaintext key.
    let status = format!
    (
        "wrote {} bytes to '{out_path}' ({} payload + 24 header + 64 signature)\n",
        image.len(),
        payload.len()
    );
    let mut err = std::io::stderr();
    match err.write_all(status.as_bytes()).and_then(|()| err.flush())
    {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => return Err(format!("cannot write status to stderr: {e}")),
    }
    Ok(())
}

fn run_derive_pubkey(args: &[String]) -> Result<(), ToolError>
{
    let key_file = take_value(args, "--key-file")?;
    let public =
    {
        // The key and the signer must drop and zeroize inside this scope, before any
        // stdout write. write_stdout may exit the process on a broken pipe, which
        // skips destructors, so no secret may still be live past this point. The
        // returned public key is not secret.
        let key = load_key(key_file)?;
        let signer = SoftwareSigner::from_key(&key)
            .map_err(|e| format!("the key from '{key_file}' is unusable: {e}"))?;
        signer.public_key()
    };

    let mut text = String::new();

    // Hex form, one line, lowercase. This is the uncompressed SEC1 point, so it
    // starts with the 04 tag.
    let mut hex = String::with_capacity(PUBKEY_HEX_LEN);
    push_hex(&mut hex, &public);
    text.push_str(&format!("public key (hex, uncompressed SEC1): {hex}\n"));

    // Ready-to-paste Rust array literal, eight bytes per line to match the style
    // already used for the pinned key in the firmware. This is a public key, so the
    // pin site decides the visibility: set it to pub or pub(crate) as fits.
    text.push_str("// set visibility to suit the pin site (pub or pub(crate))\n");
    text.push_str(&format!("pub const ROOT_KEY: [u8; {ROOT_KEY_LEN}] = [\n"));
    for row in public.chunks(8)
    {
        let mut line = String::from("    ");
        for byte in row
        {
            line.push_str(&format!("0x{byte:02x}, "));
        }
        text.push_str(line.trim_end());
        text.push('\n');
    }
    text.push_str("];\n");

    write_stdout(&text)
}

// Reads a little-endian u32 at `off` from a byte slice. Returns None if the
// slice is too short, so no read can panic.
fn read_u32_le_at(bytes: &[u8], off: usize) -> Option<u32>
{
    let arr: [u8; 4] = bytes.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

// True when `bytes` begins with the 4-byte ELF magic.
fn is_elf(bytes: &[u8]) -> bool
{
    bytes.get(..4) == Some(&[0x7f, b'E', b'L', b'F'])
}

// Creates a fresh, exclusively-owned intermediate file in the system temp dir
// and returns its path. The name mixes the pid, a monotonic counter, and a
// process-random value from std's RandomState, and the file is created with
// create_new (O_EXCL), so an attacker cannot pre-plant a symlink at a guessable
// path and redirect the objcopy output. On the rare name collision it retries.
// The caller owns the returned path and removes it after reading.
fn create_unique_temp(name: &str) -> Result<PathBuf, ToolError>
{
    // A monotonic per-process counter so two calls in one process never collide.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    for _ in 0..64u32
    {
        // RandomState is seeded from the OS at construction, so this hash is an
        // unpredictable per-attempt value.
        let mut hasher =
            std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(seq);
        hasher.write_u32(std::process::id());
        let token = hasher.finish();

        let candidate = env::temp_dir().join(format!(
            "image-signer-{name}-{}-{seq}-{token:016x}.bin",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(e) =>
            {
                return Err(format!(
                    "cannot create a temp file for the {name} objcopy output: {e}"
                ));
            }
        }
    }
    Err(format!(
        "cannot create a unique temp file for the {name} objcopy output"
    ))
}

// Converts an ELF at `path` to a flat binary with arm-none-eabi-objcopy and
// returns its bytes. The intermediate file is a fresh exclusively-created temp
// file, removed after it is read.
fn objcopy_to_binary(path: &str, name: &str) -> Result<Vec<u8>, ToolError>
{
    let tmp = create_unique_temp(name)?;
    let tmp_str = tmp
        .to_str()
        .ok_or_else(|| String::from("the temp path is not valid UTF-8"))?;

    let status = Command::new("arm-none-eabi-objcopy")
        .args(["-O", "binary", path, tmp_str])
        .status()
        .map_err(|e| format!("cannot run arm-none-eabi-objcopy on '{path}': {e}"))?;
    if !status.success()
    {
        return Err(format!(
            "arm-none-eabi-objcopy failed on '{path}' with {status}"
        ));
    }

    let bytes = fs::read(&tmp)
        .map_err(|e| format!("cannot read objcopy output '{tmp_str}': {e}"))?;
    // The intermediate is best-effort cleanup: a failure to remove it is not a
    // reason to fail the build.
    let _ = fs::remove_file(&tmp);
    Ok(bytes)
}

// Validates a flat firmware binary carries an ARMv8-M vector table at its base: the
// first word is an initial MSP in SRAM and the second is a Thumb reset vector inside
// the image's own flash band. A wrong objcopy base or a mislinked ELF fails here,
// before any byte lands in the bank, which is the B1 class the packaging tool exists
// to catch.
fn check_reset_vector
(
    bytes: &[u8],
    origin: u32,
    name: &str,
)
    -> Result<(), ToolError>
{
    let msp = read_u32_le_at(bytes, 0).ok_or_else(||
    {
        format!("the {name} image is too small to hold a vector table")
    })?;
    let reset = read_u32_le_at(bytes, 4).ok_or_else(||
    {
        format!("the {name} image is too small to hold a vector table")
    })?;

    if !(SRAM_LOW..SRAM_HIGH).contains(&msp)
    {
        return Err(format!(
            "the {name} image initial MSP {msp:#010x} is not in SRAM \
             [{SRAM_LOW:#010x}, {SRAM_HIGH:#010x}), the load base is wrong \
             (expected origin {origin:#010x})"
        ));
    }

    let end = origin.saturating_add(bytes.len() as u32);
    let reset_addr = reset & !1;
    if reset & 1 == 0 || reset_addr < origin || reset_addr >= end
    {
        return Err(format!(
            "the {name} image reset vector {reset:#010x} is not a Thumb address \
             in [{origin:#010x}, {end:#010x}), the objcopy base or link origin \
             is wrong"
        ));
    }
    Ok(())
}

// Loads a firmware region as a flat binary. An ELF is converted with objcopy, a
// raw .bin is used as-is. Either way the vector table is validated against the
// link origin so a wrong placement is refused.
fn load_region
(
    path: &str,
    origin: u32,
    name: &str,
)
    -> Result<Vec<u8>, ToolError>
{
    let raw = fs::read(path)
        .map_err(|e| format!("cannot read {name} file '{path}': {e}"))?;
    let bytes = if is_elf(&raw)
    {
        objcopy_to_binary(path, name)?
    }
    else
    {
        raw
    };
    check_reset_vector(&bytes, origin, name)?;
    Ok(bytes)
}

// Loads the pinned root public key file, which must be exactly ROOT_KEY_LEN
// bytes (an uncompressed SEC1 point). The bytes are public, so no zeroizing.
fn load_root_key(path: &str) -> Result<[u8; ROOT_KEY_LEN], ToolError>
{
    let raw = fs::read(path)
        .map_err(|e| format!("cannot read root key file '{path}': {e}"))?;
    let got = raw.len();
    raw.as_slice().try_into().map_err(|_|
    {
        format!(
            "root key file '{path}' must be exactly {ROOT_KEY_LEN} bytes \
             (uncompressed SEC1), got {got}"
        )
    })
}

fn run_assemble_bank(args: &[String]) -> Result<(), ToolError>
{
    let boot_path = take_value(args, "--boot")?;
    let secure_path = take_value(args, "--secure")?;
    let ns_path = take_value(args, "--nonsecure")?;
    let root_key_path = take_value(args, "--root-key-file")?;
    let out_path = take_value(args, "--out")?;

    let version = ImageVersion
    {
        major: parse_u8(args, "--major")?,
        minor: parse_u8(args, "--minor")?,
        revision: parse_u16(args, "--revision")?,
        build: parse_u32(args, "--build")?,
    };
    let security_counter = parse_u32(args, "--security-counter")?;

    let boot = load_region(boot_path, BOOT_ORIGIN, "boot-stage")?;
    let secure = load_region(secure_path, SECURE_ORIGIN, "secure")?;
    let nonsecure = load_region(ns_path, NS_ORIGIN, "nonsecure")?;
    let root_key = load_root_key(root_key_path)?;

    // The bring-up scalar and the signer live only inside this scope so they drop and
    // zeroize before the manifest write, which may exit on a broken pipe (skipping
    // destructors). The scalar is never printed.
    let bank =
    {
        let scalar: Zeroizing<[u8; KEY_LEN]> =
            Zeroizing::new(Sha256::digest(BRINGUP_PHRASE).into());
        let signer = SoftwareSigner::from_key(&scalar)
            .map_err(|e| format!("the bring-up scalar is unusable: {e}"))?;
        assemble_bank(
            &boot,
            &secure,
            &nonsecure,
            version,
            security_counter,
            &signer,
            &root_key,
        )
        .map_err(|e| format!("assemble-bank failed: {e}"))?
    };

    fs::write(out_path, &bank.image)
        .map_err(|e| format!("cannot write output file '{out_path}': {e}"))?;

    let manifest = build_manifest(&bank, out_path, KeyProvenance::BringUpDerived);

    // An optional manifest file. The stdout copy is authoritative for the operator,
    // the file is a convenience. A present-but-valueless --manifest is a user error.
    if let Some(manifest_path) = take_optional_value(args, "--manifest")?
    {
        fs::write(manifest_path, &manifest).map_err(|e|
        {
            format!("cannot write manifest file '{manifest_path}': {e}")
        })?;
    }

    write_stdout(&manifest)
}

// Prepare step of the external-signature flow. Loads the three firmware images
// exactly as assemble-bank does (objcopy plus vector check), builds the digest and
// the context, writes them out, and prints what the operator must sign. No key is
// touched here, and nothing secret is produced: the digest and the images are
// public.
fn run_prepare_external(args: &[String]) -> Result<(), ToolError>
{
    let boot_path = take_value(args, "--boot")?;
    let secure_path = take_value(args, "--secure")?;
    let ns_path = take_value(args, "--nonsecure")?;
    let digest_path = take_value(args, "--digest")?;
    let context_path = take_value(args, "--context")?;

    let version = ImageVersion
    {
        major: parse_u8(args, "--major")?,
        minor: parse_u8(args, "--minor")?,
        revision: parse_u16(args, "--revision")?,
        build: parse_u32(args, "--build")?,
    };
    let security_counter = parse_u32(args, "--security-counter")?;

    let boot = load_region(boot_path, BOOT_ORIGIN, "boot-stage")?;
    let secure = load_region(secure_path, SECURE_ORIGIN, "secure")?;
    let nonsecure = load_region(ns_path, NS_ORIGIN, "nonsecure")?;

    let prepared =
        prepare_external(&boot, &secure, &nonsecure, version, security_counter)
            .map_err(|e| format!("prepare-external failed: {e}"))?;

    fs::write(digest_path, prepared.digest)
        .map_err(|e| format!("cannot write digest file '{digest_path}': {e}"))?;
    fs::write(context_path, &prepared.context)
        .map_err(|e| format!("cannot write context file '{context_path}': {e}"))?;

    // An optional hex copy of the digest, one line, for a signer that wants hex.
    if let Some(hex_path) = take_optional_value(args, "--digest-hex")?
    {
        let mut hex = String::with_capacity(DIGEST_LEN * 2);
        push_hex(&mut hex, &prepared.digest);
        hex.push('\n');
        fs::write(hex_path, &hex).map_err(|e|
        {
            format!("cannot write digest-hex file '{hex_path}': {e}")
        })?;
    }

    let mut hex = String::with_capacity(DIGEST_LEN * 2);
    push_hex(&mut hex, &prepared.digest);

    let text = format!(
        "prepare-external complete, NOTHING was signed here\n\
         ==================================================\n\
         digest file  : {digest_path} ({DIGEST_LEN} raw bytes)\n\
         context file : {context_path}\n\
         digest (hex) : {hex}\n\
         payload      : {} bytes (secure {} padded + NS {})\n\
         \n\
         SIGN THE DIGEST OFFLINE, then run finalize-external:\n\
         - sign the {DIGEST_LEN}-byte digest as a RAW ECDSA P-256 signature over\n\
           the hash. The card signs the hash bytes, it must NOT re-hash them.\n\
         - on a YubiKey PIV slot this is a touch plus PIN operation.\n\
         - feed the resulting signature (raw 64-byte r||s or ASN.1 DER) plus this\n\
           context and the pinned public key to finalize-external.\n",
        prepared.payload_len, prepared.secure_len, prepared.ns_len
    );
    write_stdout(&text)
}

// Finalize step of the external-signature flow. Ingests the context, the offline
// signature, and the pinned public key, then normalizes to low-s, verifies, lays out
// the bank, and self-verifies inside finalize_external. A signature that does not
// verify writes no artifact. No key material is present at any point.
fn run_finalize_external(args: &[String]) -> Result<(), ToolError>
{
    let context_path = take_value(args, "--context")?;
    let signature_path = take_value(args, "--signature")?;
    let pubkey_path = take_value(args, "--pubkey")?;
    let out_path = take_value(args, "--out")?;

    let sig_format = match take_optional_value(args, "--sig-format")?
    {
        None | Some("auto") => SigFormat::Auto,
        Some("raw") => SigFormat::Raw,
        Some("der") => SigFormat::Der,
        Some(other) =>
        {
            return Err(format!(
                "--sig-format must be 'raw', 'der', or 'auto', got '{other}'"
            ));
        }
    };

    let context = fs::read(context_path)
        .map_err(|e| format!("cannot read context file '{context_path}': {e}"))?;
    let signature_bytes = fs::read(signature_path).map_err(|e|
    {
        format!("cannot read signature file '{signature_path}': {e}")
    })?;
    let pubkey = load_root_key(pubkey_path)?;

    let signature = parse_signature(&signature_bytes, sig_format)
        .map_err(|e| format!("cannot parse the external signature: {e}"))?;

    let bank = finalize_external(&context, &signature, &pubkey)
        .map_err(|e| format!("finalize-external failed: {e}"))?;

    fs::write(out_path, &bank.image)
        .map_err(|e| format!("cannot write output file '{out_path}': {e}"))?;

    let manifest =
        build_manifest(&bank, out_path, KeyProvenance::ExternalVerified);

    // An optional manifest file, same posture as assemble-bank: the stdout copy is
    // authoritative, the file is a convenience. A present-but-valueless --manifest is
    // a user error, never a silent no-op.
    if let Some(manifest_path) = take_optional_value(args, "--manifest")?
    {
        fs::write(manifest_path, &manifest).map_err(|e|
        {
            format!("cannot write manifest file '{manifest_path}': {e}")
        })?;
    }

    write_stdout(&manifest)
}

// Where the pinned public key reported in a manifest comes from, so the manifest
// attests the true fact for the path that built the bank. The two paths differ:
// assemble-bank derives the key and confirms it equals --root-key-file,
// finalize-external verifies an external signature against an arbitrary --pubkey.
enum KeyProvenance
{
    // The bring-up path: the key was derived from the bring-up phrase and
    // confirmed equal to the pinned --root-key-file.
    BringUpDerived,
    // The production path: an external signature was verified against the pinned
    // --pubkey, with no derivation and no equality check.
    ExternalVerified,
}

// Builds the human-readable manifest.
fn build_manifest
(
    bank: &image_signer::AssembledBank,
    out_path: &str,
    provenance: KeyProvenance,
)
    -> String
{
    let mut hex = String::new();
    push_hex(&mut hex, &bank.public_key);

    let (key_label, key_attestation) = match provenance
    {
        KeyProvenance::BringUpDerived =>
        (
            "bring-up public key",
            "  (derived from the bring-up phrase, confirmed EQUAL to --root-key-file)\n",
        ),
        KeyProvenance::ExternalVerified =>
        (
            "public key",
            "  (the external signature was verified against this pinned key)\n",
        ),
    };

    let mut text = String::new();
    text.push_str("patina_key bank image assembled and SELF-VERIFIED\n");
    text.push_str("=================================================\n");
    text.push_str(&format!("artifact               : {out_path}\n"));
    text.push_str(&format!(
        "artifact size          : {} bytes (one physical bank)\n",
        bank.image.len()
    ));
    text.push('\n');
    text.push_str(
        "Region placement (region : bank offset -> alias address : length).\n"
    );
    text.push_str(
        "Each region uses the alias matching its own SECWM band:\n"
    );
    text.push_str(&format!(
        "  {:<10} : offset {BOOT_OFFSET:#08x} -> {:#010x} {:<12} : {} bytes\n",
        "boot stage",
        BANK_BASE_SECURE + BOOT_OFFSET as u32,
        "(secure)",
        bank.boot_len
    ));
    text.push_str(&format!(
        "  {:<10} : offset {DESCRIPTOR_OFFSET:#08x} -> {:#010x} {:<12} : \
         88 bytes (header 24 + sig 64)\n",
        "descriptor",
        BANK_BASE_SECURE + DESCRIPTOR_OFFSET as u32,
        "(secure)"
    ));
    text.push_str(&format!(
        "  {:<10} : offset {SECURE_OFFSET:#08x} -> {:#010x} {:<12} : \
         {} bytes in the {SECURE_LEN}-byte band\n",
        "secure app",
        BANK_BASE_SECURE + SECURE_OFFSET as u32,
        "(secure)",
        bank.secure_len
    ));
    text.push_str(&format!(
        "  {:<10} : offset {NS_OFFSET:#08x} -> {:#010x} {:<12} : \
         {} bytes in the {NS_LEN}-byte band\n",
        "NS app",
        BANK_BASE_NS + NS_OFFSET as u32,
        "(non-secure)",
        bank.ns_len
    ));
    text.push('\n');
    text.push_str(&format!(
        "secure band length     : {SECURE_LEN} bytes (0x{SECURE_LEN:x}, pages 10-19)\n"
    ));
    text.push_str(&format!(
        "NS band length         : {NS_LEN} bytes (0x{NS_LEN:x}, pages 20-31)\n"
    ));
    text.push_str(&format!(
        "signed payload length  : {} bytes (secure {SECURE_LEN} + NS {})\n",
        bank.payload_len, bank.ns_len
    ));
    text.push('\n');
    text.push_str(&format!("{key_label:<23}: {hex}\n"));
    text.push_str(key_attestation);
    text.push_str("self-verify            : PASS (four-segment device verify accepts)\n");
    text.push('\n');
    text.push_str(
        "FLASHING PROCEDURE: NOTHING may be flashed until the option bytes are\n"
    );
    text.push_str(
        "provisioned: SECWM1=[0,19], SECWM2=[0,19], SECBOOTADD0=0x0C004000, and\n"
    );
    text.push_str(
        "the target bank ERASED FIRST.\n"
    );
    text
}

#[cfg(test)]
mod tests
{
    use super::*;

    // A successful write is classified as Done, the normal happy path.
    #[test]
    fn classify_write_ok_is_done()
    {
        match classify_write(Ok(()))
        {
            WriteOutcome::Done =>
            {}
            _ => panic!("Ok must map to Done"),
        }
    }

    #[test]
    fn classify_write_broken_pipe_is_reader_closed()
    {
        let err = std::io::Error::from(std::io::ErrorKind::BrokenPipe);
        match classify_write(Err(err))
        {
            WriteOutcome::ReaderClosed =>
            {}
            _ => panic!("a broken pipe must map to ReaderClosed"),
        }
    }

    // Any other error kind is a real failure carried up as a ToolError, never a
    // silent clean exit.
    #[test]
    fn classify_write_other_error_is_failed()
    {
        let err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        match classify_write(Err(err))
        {
            WriteOutcome::Failed(message) =>
            {
                assert!(
                    message.contains("cannot write to stdout"),
                    "the failure message must name the stdout write: {message}"
                );
            }
            _ => panic!("a non-broken-pipe error must map to Failed"),
        }
    }

    // A second non-broken-pipe kind also maps to Failed, proving the arm is the
    // catch-all rather than tied to one specific kind.
    #[test]
    fn classify_write_other_kind_also_failed()
    {
        let err = std::io::Error::from(std::io::ErrorKind::Other);
        match classify_write(Err(err))
        {
            WriteOutcome::Failed(_) =>
            {}
            _ => panic!("any other error kind must map to Failed"),
        }
    }

    // read_u32_le_at reads a little-endian word at a valid offset.
    #[test]
    fn read_u32_le_at_reads_a_valid_word()
    {
        let bytes = [0x78, 0x56, 0x34, 0x12, 0xAA];
        assert_eq!(read_u32_le_at(&bytes, 0), Some(0x1234_5678));
        assert_eq!(read_u32_le_at(&bytes, 1), Some(0xAA12_3456));
    }

    // The last in-bounds offset is len-4, the exact boundary that still reads.
    #[test]
    fn read_u32_le_at_reads_the_last_in_bounds_word()
    {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            read_u32_le_at(&bytes, 4),
            Some(u32::from_le_bytes([5, 6, 7, 8]))
        );
    }

    // An offset that would read past the end returns None rather than panicking.
    #[test]
    fn read_u32_le_at_rejects_an_out_of_range_offset()
    {
        let four = [1u8, 2, 3, 4];
        assert_eq!(read_u32_le_at(&four, 1), None);
        assert_eq!(read_u32_le_at(&four, 5), None);
        let three = [1u8, 2, 3];
        assert_eq!(read_u32_le_at(&three, 0), None);
        assert_eq!(read_u32_le_at(&[], 0), None);
    }

    // is_elf accepts the 4-byte ELF magic, with or without a trailing byte.
    #[test]
    fn is_elf_detects_the_magic()
    {
        assert!(is_elf(&[0x7f, b'E', b'L', b'F']));
        assert!(is_elf(&[0x7f, b'E', b'L', b'F', 0x01]));
    }

    // is_elf rejects non-ELF and any input shorter than the 4-byte magic.
    #[test]
    fn is_elf_rejects_non_elf_and_short_input()
    {
        assert!(!is_elf(b"\x7fELX"));
        assert!(!is_elf(b"raw firmware bytes"));
        assert!(!is_elf(&[0x7f, b'E', b'L']));
        assert!(!is_elf(&[]));
    }

    // Builds a minimal flat image with an ARMv8-M vector table: MSP then the
    // reset vector, padded to `len`.
    fn vector_table(msp: u32, reset: u32, len: usize) -> Vec<u8>
    {
        let mut b = vec![0u8; len.max(8)];
        b[0..4].copy_from_slice(&msp.to_le_bytes());
        b[4..8].copy_from_slice(&reset.to_le_bytes());
        b
    }

    #[test]
    fn check_reset_vector_accepts_a_well_formed_table()
    {
        let origin = 0x0C01_4000;
        let img = vector_table(0x2000_1000, (origin + 0x100) | 1, 0x400);
        assert!(check_reset_vector(&img, origin, "secure").is_ok());
    }

    // Fewer than eight bytes cannot hold both vector words, so it is refused.
    #[test]
    fn check_reset_vector_rejects_a_too_small_image()
    {
        let tiny = [0u8; 4];
        assert!(check_reset_vector(&tiny, 0x0C01_4000, "secure").is_err());
    }

    // An initial MSP outside the SRAM window signals a wrong load base.
    #[test]
    fn check_reset_vector_rejects_an_msp_outside_sram()
    {
        let origin = 0x0C01_4000;
        let below = vector_table(SRAM_LOW - 1, (origin + 0x100) | 1, 0x400);
        assert!(check_reset_vector(&below, origin, "secure").is_err());
        // SRAM_HIGH is the exclusive top, so an MSP equal to it is rejected.
        let top = vector_table(SRAM_HIGH, (origin + 0x100) | 1, 0x400);
        assert!(check_reset_vector(&top, origin, "secure").is_err());
    }

    // A reset vector with bit0 clear is not a Thumb address.
    #[test]
    fn check_reset_vector_rejects_a_non_thumb_reset()
    {
        let origin = 0x0C01_4000;
        let img = vector_table(0x2000_1000, origin + 0x100, 0x400);
        assert!(check_reset_vector(&img, origin, "secure").is_err());
    }

    // A reset vector below the origin or past the image end signals a mislinked
    // ELF or a wrong objcopy base.
    #[test]
    fn check_reset_vector_rejects_a_reset_outside_the_band()
    {
        let origin = 0x0C01_4000;
        let below = vector_table(0x2000_1000, (origin - 0x100) | 1, 0x400);
        assert!(check_reset_vector(&below, origin, "secure").is_err());
        let above = vector_table(0x2000_1000, (origin + 0x1000) | 1, 0x400);
        assert!(check_reset_vector(&above, origin, "secure").is_err());
    }

    // Two calls create two distinct, actually-existing temp files, so the
    // objcopy intermediate never reuses a guessable shared path.
    #[test]
    fn create_unique_temp_makes_distinct_existing_files()
    {
        let a = create_unique_temp("unit").expect("first temp");
        let b = create_unique_temp("unit").expect("second temp");
        assert!(a.exists(), "the temp file must exist after creation");
        assert!(b.exists(), "the temp file must exist after creation");
        assert_ne!(a, b, "two calls must yield distinct paths");
        let _ = fs::remove_file(&a);
        let _ = fs::remove_file(&b);
    }
}
