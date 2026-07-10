//! Command-line front end for the patina_key firmware-image signer.
//!
//! Two subcommands:
//!
//! - `sign`: signs a firmware binary into a complete signed image.
//! - `derive-pubkey`: prints the public key for a seed, so the operator can pin
//!   it into the firmware.
//!
//! Both subcommands take the 32-byte signing seed through `--key-file <PATH>`.
//! The value is either a filesystem path or the single character `-`, which
//! reads the seed from STDIN. The stdin form lets a decrypted seed be piped in
//! (for example from `gpg --decrypt`). 
//! The tool never accepts the key bytes as a literal argument, so the seed cannot
//! leak through a process listing or shell history.
//!
//! Arguments are parsed by hand over `std::env::args`, with NO parsing
//! dependency. Every bad input fails closed: a clear message to stderr and a
//! non-zero exit. The binary never panics on user input.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::process::ExitCode;

use image_signer::ImageSigner;
use image_signer::SoftwareSigner;
use image_signer::build_signed_image;
use image_verify::ImageVersion;
use zeroize::Zeroizing;

// The number of seed bytes the tool accepts. An Ed25519 seed is exactly this
// many bytes (RFC 8032).
const SEED_LEN: usize = 32;

// A clear error string carried up to the top-level handler, which prints it to
// stderr and exits non-zero.
type ToolError = String;

// The classified result of a stdout write, decided WITHOUT touching any I/O so
// the decision is unit-testable on synthetic errors.
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
// Callers MUST drop every secret (the seed, the signer) BEFORE calling this. A
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
            // The reader closed its end because it already received the output
            // it wanted. Nothing more is wanted, so exit quietly and
            // successfully. The bytes from this failed write were NOT delivered,
            // that is fine, the consumer is gone.
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

// Dispatches on the subcommand. argv[0] is the program name.
fn run(args: &[String]) -> Result<(), ToolError>
{
    let command = args.get(1).map(String::as_str);
    match command
    {
        Some("sign") => run_sign(&args[2..]),
        Some("derive-pubkey") => run_derive_pubkey(&args[2..]),
        Some("--help") | Some("-h") | None => print_usage(),
        Some(other) => Err(format!(
            "unknown subcommand '{other}', expected 'sign' or 'derive-pubkey'"
        )),
    }
}

// An explicit help request prints usage to stdout so it can be piped. The
// error path for bad args never calls this: it returns an Err that main prints
// to stderr with a non-zero exit.
fn print_usage() -> Result<(), ToolError>
{
    let usage = "\
patina_key firmware-image signer

USAGE:
  image-signer sign --payload <FILE> --key-file <PATH> --out <FILE> \\
    --major <N> --minor <N> --revision <N> --build <N> \\
    --security-counter <N> [--expect-pubkey <HEX>]

  image-signer derive-pubkey --key-file <PATH>

  --key-file takes a path to a 32-byte seed, or '-' to read the seed
  from stdin (for example: gpg --decrypt seed.gpg | image-signer ... \\
  --key-file -). The seed is never passed as a literal argument.

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

// Parses exactly 64 hex chars into a 32-byte public key. Fails closed on a
// wrong length or any non-hex char. No dependency, no panic.
fn parse_pubkey_hex(hex: &str) -> Result<[u8; 32], ToolError>
{
    let bytes = hex.as_bytes();
    if bytes.len() != 64
    {
        return Err(format!(
            "--expect-pubkey must be 64 hex chars (32 bytes), got {} chars",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate()
    {
        let hi = hex_nibble(bytes[i * 2])
            .ok_or_else(|| String::from("--expect-pubkey has a non-hex char"))?;
        let lo = hex_nibble(bytes[i * 2 + 1])
            .ok_or_else(|| String::from("--expect-pubkey has a non-hex char"))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

// Loads the seed named by the `--key-file` value and validates it is EXACTLY 32
// bytes. The value is either `-`, which reads the raw seed from stdin, or a
// filesystem path.
fn load_seed(key_file: &str) -> Result<Zeroizing<[u8; SEED_LEN]>, ToolError>
{
    // For stdin, label the source "stdin" so a wrong-length error names the
    // real origin rather than the literal '-'. For a path, the path is the
    // label.
    let (raw, source) = if key_file == "-"
    {
        (read_stdin_bytes()?, "stdin")
    }
    else
    {
        let bytes = Zeroizing::new
        (
            fs::read(key_file)
                .map_err(|e| format!("cannot read seed file '{key_file}': {e}"))?,
        );
        (bytes, key_file)
    };
    seed_from_bytes(&raw, source)
}

// Reads stdin to end into a Zeroizing buffer. The decrypted seed can be piped in
// with no cleartext file on disk. The bytes are wiped when the buffer drops.
fn read_stdin_bytes() -> Result<Zeroizing<Vec<u8>>, ToolError>
{
    // Pre-size to SEED_LEN + 1 so a 32-byte seed needs no growth (no seed copy
    // left in a freed allocation), while the +1 still lets an over-long input be
    // read and rejected by the length check.
    let mut buffer = Zeroizing::new(Vec::with_capacity(SEED_LEN + 1));
    std::io::stdin()
        .read_to_end(&mut buffer)
        .map_err(|e| format!("cannot read seed from stdin: {e}"))?;
    Ok(buffer)
}

// Validates raw seed bytes are EXACTLY 32 long and copies them into a fixed
// Zeroizing array. A trailing newline or any extra byte makes the length wrong,
// so it fails closed, which is the intended behavior. The `source` label names
// the origin so the error message points the operator at the right input.
fn seed_from_bytes
(
    raw: &[u8],
    source: &str,
)
    -> Result<Zeroizing<[u8; SEED_LEN]>, ToolError>
{
    let got = raw.len();
    let arr: [u8; SEED_LEN] = raw.try_into().map_err(|_| format!(
        "seed from '{source}' must be exactly {SEED_LEN} bytes, got {got}"
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
    let seed = load_seed(key_file)?;

    let signer = SoftwareSigner::from_seed(&seed);

    // Optional guard against signing with the wrong key file. If the operator
    // supplies an expected public key, it must equal the key the signer reports
    // BEFORE any image is written, else the tool fails closed.
    if let Ok(expected_hex) = take_value(args, "--expect-pubkey")
    {
        let expected = parse_pubkey_hex(expected_hex)?;
        if expected != signer.public_key()
        {
            return Err(String::from(
                "--expect-pubkey does not match the seed's public key, \
                 refusing to sign with the wrong key"
            ));
        }
    }

    let image = build_signed_image(&payload, version, security_counter, &signer)
        .map_err(|e| format!("signing failed: {e}"))?;

    fs::write(out_path, &image)
        .map_err(|e| format!("cannot write output file '{out_path}': {e}"))?;

    // Informational status line on stderr. The image is already written, so this
    // line must never decide the outcome. A broken stderr pipe is swallowed
    // rather than exiting the process, because the seed and signer are still live
    // here and their destructors MUST run to wipe the plaintext seed.
    let status = format!(
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
        // The seed and the signer must drop and zeroize INSIDE this scope,
        // before any stdout write. write_stdout may exit the process on a broken
        // pipe, which skips destructors, so no secret may still be live past this
        // point. The returned public key is not secret.
        let seed = load_seed(key_file)?;
        let signer = SoftwareSigner::from_seed(&seed);
        signer.public_key()
    };

    let mut text = String::new();

    // Hex form, one line, lowercase.
    let mut hex = String::with_capacity(public.len() * 2);
    push_hex(&mut hex, &public);
    text.push_str(&format!("public key (hex): {hex}\n"));

    // Ready-to-paste Rust array literal, four bytes per line to match the style
    // already used for the pinned key in the firmware. This is a PUBLIC key, so
    // the pin site decides the visibility: set it to pub or pub(crate) as fits.
    text.push_str("// set visibility to suit the pin site (pub or pub(crate))\n");
    text.push_str("pub const ROOT_KEY: [u8; 32] = [\n");
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
}
