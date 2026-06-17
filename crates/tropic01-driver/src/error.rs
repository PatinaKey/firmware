//! Layered, transport-agnostic error model for the TROPIC01 driver.
//!
//! Per-layer `Copy` enums fold upward into the public `SeError` via `From`.
//! No stringly errors. The L1 seam erases the concrete `SpiDevice::Error` to
//! `L1Error::Bus`, so the public surface stays non-generic.

use crate::ids::L2Status;
use crate::ids::L3Status;

/// Layer 1 (SPI transport + chip-status poll) errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L1Error
{
    /// The underlying SPI bus reported a failure.
    Bus,
    /// The chip stayed busy past the allowed deadline.
    ChipBusy,
    /// The chip signalled Alarm Mode.
    Alarm,
    /// The CHIP_STATUS byte did not match any known pattern.
    BadChipStatus,
}

/// Layer 2 (frame build/parse + CRC) errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L2Error
{
    /// CRC16 mismatch on a received frame.
    Crc,
    /// The frame structure was malformed (e.g. length field out of range).
    BadFrame,
    /// The supplied byte slice was too short to hold a full frame.
    ShortFrame,
    /// The chip returned a non-OK L2 status byte.
    Status(L2Status),
    /// A layer 1 error occurred while moving the frame.
    L1(L1Error),
}

/// Layer 3 (encrypted command/result) errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Error
{
    /// AES-GCM authentication tag verification failed.
    Tag,
    /// A crypto primitive failed unexpectedly.
    Crypto,
    /// The chip returned a non-OK L3 result status.
    Result(L3Status),
    /// An L3 packet or RES_DATA length violated a structural size bound (too
    /// long, too short, or not the expected size).
    Oversize,
    /// Bounds-checked parsing of an L3 payload failed.
    Parse(ParseError),
    /// A layer 2 error occurred while transporting the L3 packet.
    L2(L2Error),
}

/// Noise KK1 handshake errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError
{
    /// The device certificate chain failed validation.
    BadCert,
    /// The handshake authentication tag did not verify.
    BadAuthTag,
    /// An X25519 Diffie-Hellman step failed.
    Dh,
    /// A layer 2 error occurred during the handshake exchange.
    L2(L2Error),
}

/// X.509 certificate-store parsing errors.
///
/// Raised while extracting STPUB from the `Get_Info` cert store. The DER is
/// attacker-influenced (it comes from the chip), so every variant is a
/// fail-closed rejection. Recoverable: this runs before any session, so there
/// is nothing to poison. Maps libtropic's cert/ASN.1 return codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError
{
    /// The store header was wrong (bad version or num_certs) or a declared
    /// length truncated the header or the DEVICE certificate. Maps libtropic
    /// `LT_CERT_STORE_INVALID`.
    BadStore,
    /// A DER feature the parser does not support: a length in long-form over 2
    /// bytes or indefinite, or nesting deeper than the depth cap. Maps libtropic
    /// `LT_CERT_UNSUPPORTED`.
    Unsupported,
    /// No X25519 key object was found in the DEVICE certificate. Maps libtropic
    /// `LT_CERT_ITEM_NOT_FOUND`.
    KeyNotFound,
    /// The DER structure was otherwise malformed (a bounds or structure fault
    /// while walking the certificate).
    Malformed,
}

/// X.509 certificate-chain signature-verification errors.
///
/// Raised while verifying the DEVICE -> ... -> pinned-root signature path of the
/// `Get_Info` cert store. The certificates are attacker-influenced (they come
/// from the chip), so every variant is a fail-closed rejection. The load-bearing
/// trust step is verifying the product CA under the caller-PINNED root key, never
/// under a key taken from the store.
#[cfg(feature = "attestation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError
{
    /// The store header declared a certificate count other than the expected 4.
    WrongCertCount,
    /// A certificate's signatureAlgorithm OID was not one of the supported
    /// ecdsa-with-SHA384 / ecdsa-with-SHA512.
    UnsupportedSigAlg,
    /// An issuer SubjectPublicKeyInfo did not hold a supported EC public key
    /// (wrong algorithm OID, wrong curve, or a malformed point).
    BadPublicKey,
    /// A signature did not verify under the issuer (or pinned-root) public key.
    /// This is the fail-closed result for any tampered or reordered certificate.
    BadSignature,
    /// A certificate's DER structure was malformed while locating the
    /// tbsCertificate, signatureAlgorithm, or signatureValue.
    Malformed,
    /// A DER length used long-form over 2 bytes or indefinite form - the same
    /// encoding the parser rejects elsewhere. Maps from the shared parse_der_len.
    Unsupported,
}

/// Firmware-image blob decoding errors.
///
/// Raised by `FwImageChunks` while splitting a length-prefixed signed firmware
/// image into its on-wire chunks. The blob is attacker-influenced (it is the
/// update payload handed to the driver), so every variant is a fail-closed
/// rejection. The driver is a faithful transport: it validates only the framing
/// LENGTH bounds, never the image's internal type/offset/version fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwImageError
{
    /// The blob exceeded the maximum firmware-update size.
    TooLong,
    /// The blob was shorter than the minimum (the 0xB0 header chunk).
    TooShort,
    /// A length prefix ran past the end of the blob (a truncated chunk).
    Truncated,
}

/// Bounds-checked parser errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError
{
    /// Not enough bytes remained to satisfy the request.
    UnexpectedEnd,
    /// A parsed field held a value outside its recognized set.
    InvalidValue,
}

/// The public, transport-agnostic driver error.
///
/// Upper layers (CTAP2 / OpenPGP / PKCS#11) see only this type. No SPI error,
/// no session handle, and no transport detail leak through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeError
{
    /// A layer 1 fault bubbled up.
    L1(L1Error),
    /// A layer 2 fault bubbled up.
    L2(L2Error),
    /// A layer 3 fault bubbled up.
    L3(L3Error),
    /// The handshake failed.
    Handshake(HandshakeError),
    /// Parsing the X.509 certificate store (STPUB extraction) failed.
    Cert(CertError),
    /// Verifying the X.509 certificate chain up to the pinned root failed.
    #[cfg(feature = "attestation")]
    Chain(ChainError),
    /// The session was torn down. Re-handshake before any further L3 command.
    SessionLost,
    /// The AES-GCM nonce counter reached its maximum. Session is fatal.
    NonceExhausted,
    /// A caller-supplied argument was invalid.
    InvalidArgument,
    /// A caller-supplied output buffer was too small for the result.
    BufferTooSmall,
    /// Decoding a firmware-image update blob failed.
    Image(FwImageError),
    /// A firmware update finished writing but the bank did not take the BOOT_V2
    /// form: a bank read back with a header whose size is not the 52-byte BOOT_V2
    /// record (it stayed empty or a BOOT_V1 record), so it was not promoted. The
    /// chip is dual-bank and recoverable, but the new firmware is not installed.
    FwUpdateIncomplete,
    /// An installed firmware bank or running firmware reported a version that
    /// does not match the supplied image. The bank was written but holds an
    /// unexpected version.
    FwVersionMismatch,
}

impl From<L1Error> for L2Error
{
    fn from(e: L1Error) -> Self
    {
        L2Error::L1(e)
    }
}

impl From<L2Error> for L3Error
{
    fn from(e: L2Error) -> Self
    {
        L3Error::L2(e)
    }
}

impl From<ParseError> for L3Error
{
    fn from(e: ParseError) -> Self
    {
        L3Error::Parse(e)
    }
}

impl From<L2Error> for HandshakeError
{
    fn from(e: L2Error) -> Self
    {
        HandshakeError::L2(e)
    }
}

impl From<L1Error> for SeError
{
    fn from(e: L1Error) -> Self
    {
        SeError::L1(e)
    }
}

impl From<L2Error> for SeError
{
    fn from(e: L2Error) -> Self
    {
        SeError::L2(e)
    }
}

impl From<L3Error> for SeError
{
    fn from(e: L3Error) -> Self
    {
        SeError::L3(e)
    }
}

impl From<HandshakeError> for SeError
{
    fn from(e: HandshakeError) -> Self
    {
        SeError::Handshake(e)
    }
}

impl From<ParseError> for SeError
{
    fn from(e: ParseError) -> Self
    {
        SeError::L3(L3Error::Parse(e))
    }
}

impl From<CertError> for SeError
{
    fn from(e: CertError) -> Self
    {
        SeError::Cert(e)
    }
}

#[cfg(feature = "attestation")]
impl From<ChainError> for SeError
{
    fn from(e: ChainError) -> Self
    {
        SeError::Chain(e)
    }
}

impl From<FwImageError> for SeError
{
    fn from(e: FwImageError) -> Self
    {
        SeError::Image(e)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn l1_folds_into_l2()
    {
        let e: L2Error = L1Error::Bus.into();
        assert_eq!(e, L2Error::L1(L1Error::Bus));
    }

    #[test]
    fn l2_folds_into_l3()
    {
        let e: L3Error = L2Error::Crc.into();
        assert_eq!(e, L3Error::L2(L2Error::Crc));
    }

    #[test]
    fn parse_folds_into_l3()
    {
        let e: L3Error = ParseError::UnexpectedEnd.into();
        assert_eq!(e, L3Error::Parse(ParseError::UnexpectedEnd));
    }

    #[test]
    fn l2_folds_into_handshake()
    {
        let e: HandshakeError = L2Error::BadFrame.into();
        assert_eq!(e, HandshakeError::L2(L2Error::BadFrame));
    }

    #[test]
    fn layers_fold_into_se_error()
    {
        let a: SeError = L1Error::Alarm.into();
        assert_eq!(a, SeError::L1(L1Error::Alarm));
        let b: SeError = L2Error::Crc.into();
        assert_eq!(b, SeError::L2(L2Error::Crc));
        let c: SeError = L3Error::Tag.into();
        assert_eq!(c, SeError::L3(L3Error::Tag));
        let d: SeError = HandshakeError::Dh.into();
        assert_eq!(d, SeError::Handshake(HandshakeError::Dh));
    }

    #[test]
    fn cert_folds_into_se_error()
    {
        let e: SeError = CertError::KeyNotFound.into();
        assert_eq!(e, SeError::Cert(CertError::KeyNotFound));
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn chain_folds_into_se_error()
    {
        let e: SeError = ChainError::BadSignature.into();
        assert_eq!(e, SeError::Chain(ChainError::BadSignature));
    }

    #[test]
    fn fw_image_folds_into_se_error()
    {
        let e: SeError = FwImageError::Truncated.into();
        assert_eq!(e, SeError::Image(FwImageError::Truncated));
    }

    #[test]
    fn parse_folds_all_the_way_into_se_error()
    {
        let e: SeError = ParseError::UnexpectedEnd.into();
        assert_eq!(e, SeError::L3(L3Error::Parse(ParseError::UnexpectedEnd)));
    }

    #[test]
    fn question_mark_chains_compile()
    {
        // A function returning SeError can `?` an L1Error via the chain.
        fn inner() -> Result<(), SeError>
        {
            let r: Result<(), L1Error> = Err(L1Error::ChipBusy);
            r?;
            Ok(())
        }
        assert_eq!(inner(), Err(SeError::L1(L1Error::ChipBusy)));
    }
}
