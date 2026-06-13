//! Live integration tests against the official TROPIC01 model (ts-tvl).
//!
//! These drive the REAL se-driver public API over a TCP shim that speaks the
//! model's wire protocol, so the driver runs its real Noise KK1 handshake and
//! real AES-GCM L3 codec end to end against an INDEPENDENT implementation of the
//! chip. No keys are pinned and nothing is mocked: if any byte of the protocol
//! or crypto were wrong, the handshake or a GCM tag would fail. This is the
//! strongest validation short of silicon, and it breaks the in-repo chip-mock
//! circularity for every command's success path plus the protocol-reachable
//! failure paths (slot-not-empty, counter-invalid, invalid-key).
//!
//! Gated behind the `model-itest` feature so the normal `cargo test` and CI stay
//! hermetic. Run via this crate's `scripts/model-itest.sh`, which starts the
//! model first.
//!
//! HOST TEST ONLY. Validates protocol byte-exactness, NOT physical security
//! (timing, the real TRNG, the real MAC-and-Destroy KDF, or DPA resistance).
//!
//! Injected-fault paths (corrupt GCM tag, CRC error, alarm, truncated frames)
//! are NOT covered here: the model does not misbehave on command. Those stay in
//! the in-repo mock tests. Model = real conformance. mock = fault robustness.

#![cfg(feature = "model-itest")]

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

use embedded_hal::spi::ErrorType;
use embedded_hal::spi::Operation;
use embedded_hal::spi::SpiDevice;
use zeroize::Zeroizing;

use se_driver::EccCurve;
use se_driver::EccSlot;
use se_driver::MCounterIdx;
use se_driver::MacDestroySlot;
use se_driver::RMemSlot;
use se_driver::SeCommands;
use se_driver::SeWait;
use se_driver::SessionConfig;
use se_driver::StartupId;
use se_driver::Tropic01;

// Model wire protocol (libtropic hal/posix/tcp)
//
// Each message is `[tag(1) | len(u16 LE) | payload(len)]`. The server echoes the
// tag. A logical SPI transaction is CSN_LOW, one or more full-duplex SPI_SEND
// transfers (the reply payload is the MISO bytes), then CSN_HIGH.

const MODEL_ADDR: &str = "127.0.0.1:28992";

const TAG_CSN_LOW: u8 = 0x01;
const TAG_CSN_HIGH: u8 = 0x02;
const TAG_SPI_SEND: u8 = 0x03;
const TAG_RESET_TARGET: u8 = 0x10;

// Pinned model keys (libtropic published TEST keys. NOT production)
//
// The model's `model_cfg.yml` pins the chip static key and pairing slot 0 to the
// libtropic `prod0` default test keypair. These are public test vectors.

// Chip static public key (model_cfg `s_t_pub`).
const STPUB: [u8; 32] = hex32("9508f0321cb1d2e5d1f1a4609c0541b780e6dd50d6482b6b08b2c27e7b762647");
// Host static pairing private key (libtropic `lt_sh0priv_prod0`).
const SHIPRIV: [u8; 32] = hex32("283f5a0ffc41cf5098a8e17db6372c3caad1eeeedf0f75bc3fbfcd9cab3de972");
// Host static pairing public key (libtropic `lt_sh0pub_prod0`).
const SHIPUB: [u8; 32] = hex32("f975eb3c2fd790c96f294f1557a5031780c9aafa140da28f55e7515737b2502c");
// Host ephemeral private key (fresh per session. Fixed here for determinism).
const EHPRIV: [u8; 32] = hex32("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

/// A bus error from the model shim.
#[derive(Debug)]
struct ModelError;

impl embedded_hal::spi::Error for ModelError
{
    fn kind(&self) -> embedded_hal::spi::ErrorKind
    {
        embedded_hal::spi::ErrorKind::Other
    }
}

/// A `SpiDevice` that tunnels SPI transactions to the TROPIC01 model over TCP.
struct ModelSpi
{
    stream: TcpStream,
}

impl ModelSpi
{
    /// Connects to a running model server.
    fn connect() -> Self
    {
        let stream = TcpStream::connect(MODEL_ADDR)
            .expect("connect to TROPIC01 model (is scripts/model-itest.sh running it?)");
        ModelSpi
        {
            stream,
        }
    }

    /// Sends one tagged message and returns the reply payload.
    fn msg(&mut self, tag: u8, payload: &[u8]) -> std::io::Result<Vec<u8>>
    {
        let len = u16::try_from(payload.len()).expect("payload fits u16");
        let mut header = [0u8; 3];
        header[0] = tag;
        header[1..3].copy_from_slice(&len.to_le_bytes());
        self.stream.write_all(&header)?;
        self.stream.write_all(payload)?;

        let mut rheader = [0u8; 3];
        self.stream.read_exact(&mut rheader)?;
        let rlen = u16::from_le_bytes([rheader[1], rheader[2]]) as usize;
        let mut rpayload = vec![0u8; rlen];
        self.stream.read_exact(&mut rpayload)?;
        if rheader[0] != tag
        {
            return Err(std::io::Error::other("model echoed a different tag"));
        }
        Ok(rpayload)
    }

    /// One full-duplex SPI transfer: clocks `tx`, returns the MISO bytes.
    fn spi_send(&mut self, tx: &[u8]) -> Result<Vec<u8>, ModelError>
    {
        self.msg(TAG_SPI_SEND, tx).map_err(|_| ModelError)
    }

    /// Resets the model to its configured power-on state (clean per-test state).
    ///
    /// A model-control message (not an SPI transfer), so it stays in the shim.
    /// The chip-level reboot into Application FW is `Tropic01::reboot`, exercised
    /// through the driver's public API below.
    fn reset_target(&mut self)
    {
        self.msg(TAG_RESET_TARGET, &[]).expect("reset target");
    }
}

impl ErrorType for ModelSpi
{
    type Error = ModelError;
}

impl SpiDevice for ModelSpi
{
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), ModelError>
    {
        self.msg(TAG_CSN_LOW, &[]).map_err(|_| ModelError)?;
        for op in operations.iter_mut()
        {
            match op
            {
                Operation::Write(buf) =>
                {
                    self.spi_send(buf)?;
                }
                Operation::Read(buf) =>
                {
                    let tx = vec![0u8; buf.len()];
                    let rx = self.spi_send(&tx)?;
                    copy_miso(&rx, buf);
                }
                Operation::TransferInPlace(buf) =>
                {
                    let tx = buf.to_vec();
                    let rx = self.spi_send(&tx)?;
                    copy_miso(&rx, buf);
                }
                Operation::Transfer(read, write) =>
                {
                    let rx = self.spi_send(write)?;
                    copy_miso(&rx, read);
                }
                Operation::DelayNs(_) =>
                {
                    // Model timing is irrelevant. The reply is always immediate.
                }
            }
        }
        self.msg(TAG_CSN_HIGH, &[]).map_err(|_| ModelError)?;
        Ok(())
    }
}

/// Copies the MISO reply into `buf`, zero-filling any tail the model omits.
fn copy_miso(rx: &[u8], buf: &mut [u8])
{
    let n = rx.len().min(buf.len());
    buf[..n].copy_from_slice(&rx[..n]);
    for b in buf[n..].iter_mut()
    {
        *b = 0;
    }
}

/// A no-op wait provider: the model answers immediately, so no real delay.
struct NoWait;

impl SeWait for NoWait
{
    type Error = ModelError;

    fn wait_ready(&mut self, _timeout_ms: u32) -> Result<(), ModelError>
    {
        Ok(())
    }

    fn delay_ms(&mut self, _ms: u32) -> Result<(), ModelError>
    {
        Ok(())
    }
}

/// Opens a fresh, reset, app-mode secure session against the model.
fn fresh_session() -> Tropic01<ModelSpi, NoWait, se_driver::ActiveSession>
{
    let mut spi = ModelSpi::connect();
    spi.reset_target();
    let mut dev = Tropic01::new(spi, NoWait);
    // Chip boots in Start-up Mode; reboot into Application FW (driver public API).
    dev.reboot(StartupId::Reboot).expect("reboot into Application FW");

    let ehpriv = Zeroizing::new(EHPRIV);
    let shipriv = Zeroizing::new(SHIPRIV);
    let cfg = SessionConfig
    {
        ehpriv: &ehpriv,
        shipriv: &shipriv,
        shipub: &SHIPUB,
        stpub: &STPUB,
        pkey_index: 0,
    };
    match dev.open_session(cfg)
    {
        Ok(active) => active,
        Err((_, e)) => panic!("open_session against model failed: {e:?}"),
    }
}

// Tests

#[test]
fn open_session_and_ping_small_echoes_payload()
{
    let mut se = fresh_session();
    let msg = b"patina_key vs TROPIC01 model";
    let mut out = [0u8; 28];
    let n = se.ping_into(msg, &mut out).expect("ping");
    assert_eq!(n, msg.len());
    assert_eq!(&out[..n], msg);
}

#[test]
fn ping_large_payload_round_trips_real_multi_chunk_send()
{
    // 600 bytes forces a 3-chunk L2 SEND (252/252/115) on the wire against the
    // REAL model: the live counterpart to the golden L2-frame KAT.
    let mut se = fresh_session();
    let msg: Vec<u8> = (0..600u16).map(|i| (i & 0xFF) as u8).collect();
    let mut out = [0u8; 600];
    let n = se.ping_into(&msg, &mut out).expect("large ping");
    assert_eq!(n, msg.len());
    assert_eq!(&out[..n], msg.as_slice());
}

#[test]
fn random_value_get_fills_the_buffer()
{
    let mut se = fresh_session();
    let mut out = [0u8; 32];
    let n = se.random_into(&mut out).expect("random");
    assert_eq!(n, out.len());
}

#[test]
fn rmem_write_then_read_round_trips()
{
    let mut se = fresh_session();
    let slot = RMemSlot::new(7).unwrap();
    let data = b"stored in encrypted R-memory";
    se.rmem_write(slot, data).expect("rmem write");
    // rmem_read_into requires the buffer sized to the protocol MAX up front
    // (the result length is not known to the caller): see se-driver lesson 2b.2.
    let mut out = [0u8; 512];
    let n = se.rmem_read_into(slot, &mut out).expect("rmem read");
    assert_eq!(&out[..n], data);
}

#[test]
fn rmem_write_twice_without_erase_is_recoverable()
{
    // Writing an already-written slot returns a recoverable SlotNotEmpty. The
    // session must stay live (the second call returns an error, not a teardown).
    let mut se = fresh_session();
    let slot = RMemSlot::new(9).unwrap();
    se.rmem_write(slot, b"first").expect("first write");
    let second = se.rmem_write(slot, b"second");
    assert!(second.is_err(), "second write to a written slot must fail");
    // Session still usable: a ping must still succeed.
    let mut out = [0u8; 4];
    se.ping_into(b"live", &mut out).expect("session alive after recoverable error");
    assert_eq!(&out, b"live");
}

#[test]
fn mcounter_get_uninitialized_is_recoverable_counter_invalid()
{
    let mut se = fresh_session();
    let idx = MCounterIdx::new(0).unwrap();
    let res = se.mcounter_get(idx);
    assert!(res.is_err(), "an uninitialized counter must surface an error");
    // Recoverable: the session survives.
    let mut out = [0u8; 4];
    se.ping_into(b"live", &mut out).expect("session alive after counter-invalid");
    assert_eq!(&out, b"live");
}

#[test]
fn ecc_keygen_then_public_key_p256()
{
    let mut se = fresh_session();
    let slot = EccSlot::new(1).unwrap();
    se.ecc_key_generate(slot, EccCurve::P256).expect("p256 keygen");
    let pk = se.ecc_public_key(slot).expect("read p256 pubkey");
    assert_eq!(pk.curve(), EccCurve::P256);
    assert_eq!(pk.bytes().len(), 64);
}

#[test]
fn ecc_keygen_then_public_key_ed25519()
{
    let mut se = fresh_session();
    let slot = EccSlot::new(2).unwrap();
    se.ecc_key_generate(slot, EccCurve::Ed25519).expect("ed25519 keygen");
    let pk = se.ecc_public_key(slot).expect("read ed25519 pubkey");
    assert_eq!(pk.curve(), EccCurve::Ed25519);
    assert_eq!(pk.bytes().len(), 32);
}

#[test]
fn ecc_public_key_empty_slot_is_recoverable_invalid_key()
{
    let mut se = fresh_session();
    let slot = EccSlot::new(20).unwrap();
    let res = se.ecc_public_key(slot);
    assert!(res.is_err(), "reading an empty slot must surface an error");
    let mut out = [0u8; 4];
    se.ping_into(b"live", &mut out).expect("session alive after invalid-key");
    assert_eq!(&out, b"live");
}

#[test]
fn ecdsa_sign_returns_a_signature()
{
    let mut se = fresh_session();
    let slot = EccSlot::new(3).unwrap();
    se.ecc_key_generate(slot, EccCurve::P256).expect("p256 keygen");
    let digest = [0x5Au8; 32];
    let sig = se.ecdsa_sign(slot, &digest).expect("ecdsa sign");
    assert_eq!(sig.0.len(), 64);
    assert!(sig.0.iter().any(|&b| b != 0), "signature must not be all zero");
}

#[test]
fn eddsa_sign_returns_a_signature()
{
    let mut se = fresh_session();
    let slot = EccSlot::new(4).unwrap();
    se.ecc_key_generate(slot, EccCurve::Ed25519).expect("ed25519 keygen");
    let sig = se.eddsa_sign(slot, b"sign me").expect("eddsa sign");
    assert_eq!(sig.0.len(), 64);
    assert!(sig.0.iter().any(|&b| b != 0), "signature must not be all zero");
}

#[test]
fn mac_and_destroy_returns_an_output()
{
    let mut se = fresh_session();
    let slot = MacDestroySlot::new(5).unwrap();
    let input = [0x42u8; 32];
    let out = se.mac_and_destroy(slot, &input).expect("mac and destroy");
    assert_eq!(out.expose().len(), 32);
}

#[test]
fn rmem_erase_allows_rewriting_a_slot()
{
    // The real erase-then-write flow: a second write to a written slot fails
    // (SlotNotEmpty), but after an erase the slot rewrites and reads back the new
    // value. This exercises 0x42 end to end against the model.
    let mut se = fresh_session();
    let slot = RMemSlot::new(11).unwrap();
    se.rmem_write(slot, b"first value").expect("first write");
    assert!(se.rmem_write(slot, b"second").is_err(), "rewrite without erase must fail");
    se.rmem_erase(slot).expect("erase");
    se.rmem_write(slot, b"value after erase").expect("write after erase");
    let mut out = [0u8; 512];
    let n = se.rmem_read_into(slot, &mut out).expect("read back");
    assert_eq!(&out[..n], b"value after erase");
}

#[test]
fn mcounter_init_update_get_decrements_by_one()
{
    // init sets the counter, get reads it back, update decrements by one. This
    // exercises 0x80 and 0x81 end to end and checks the decrement semantics
    // against the model (conformance, not the in-repo mock).
    let mut se = fresh_session();
    let idx = MCounterIdx::new(1).unwrap();
    se.mcounter_init(idx, 100).expect("init");
    assert_eq!(se.mcounter_get(idx).expect("get after init"), 100);
    se.mcounter_update(idx).expect("update");
    assert_eq!(se.mcounter_get(idx).expect("get after update"), 99);
}

#[test]
fn mcounter_update_uninitialized_is_recoverable()
{
    // Updating a counter that was never initialized surfaces a recoverable error
    // (CounterInvalid). The session must survive.
    let mut se = fresh_session();
    let idx = MCounterIdx::new(3).unwrap();
    let res = se.mcounter_update(idx);
    assert!(res.is_err(), "update on an uninitialized counter must fail");
    let mut out = [0u8; 4];
    se.ping_into(b"live", &mut out).expect("session alive after counter error");
    assert_eq!(&out, b"live");
}

#[test]
fn mcounter_update_to_zero_then_underflow_is_recoverable()
{
    // Initialize to 1, decrement to 0, then a further decrement underflows and
    // surfaces a recoverable error (UpdateErr per the user-API table). The
    // session stays live throughout.
    let mut se = fresh_session();
    let idx = MCounterIdx::new(4).unwrap();
    se.mcounter_init(idx, 1).expect("init to 1");
    se.mcounter_update(idx).expect("decrement to 0");
    assert_eq!(se.mcounter_get(idx).expect("get"), 0);
    let underflow = se.mcounter_update(idx);
    assert!(underflow.is_err(), "decrement below zero must fail");
    let mut out = [0u8; 4];
    se.ping_into(b"live", &mut out).expect("session alive after underflow");
    assert_eq!(&out, b"live");
}

// helpers

/// Decodes a 64-char hex string to 32 bytes at compile time.
const fn hex32(s: &str) -> [u8; 32]
{
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32
    {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Maps one hex digit to its nibble value.
const fn nib(c: u8) -> u8
{
    match c
    {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}
