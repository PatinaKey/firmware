//! Noise KK1 handshake: derives the L3 session keys and authenticates the chip.
//!
//! Reproduces the libtropic key schedule. The transcript hash chains six
//! SHA-256 steps over the protocol name and the public keys. The schedule runs
//! three X25519 DH operations folded through the custom HKDF, then the chip is
//! authenticated via the `t_tauth` GCM tag.
//!
//! CRITICAL: the first HKDF keys on the 32-byte protocol name. Every later HKDF
//! keys on the 33-byte chaining-key buffer (last byte always zero). HMAC over a
//! 32- vs 33-byte key differs, so this length must stay exact. The golden KAT
//! (`tests/oracle`) guards it.

use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::HandshakeError;
use crate::session::SessionKeys;

/// The 32-byte zero-padded Noise protocol name.
const PROTOCOL_NAME: [u8; 32] = *b"Noise_KK1_25519_AESGCM_SHA256\x00\x00\x00";

/// The keys derived by the handshake schedule (before chip authentication).
///
/// Carries secrets. `Drop` wipes every field. The type derives no `Clone`,
/// `Copy`, or `Debug`, so it cannot duplicate or print a key.
pub(crate) struct Derived
{
    /// AES-256-GCM key for the command direction.
    pub(crate) k_cmd: [u8; 32],
    /// AES-256-GCM key for the result direction.
    pub(crate) k_res: [u8; 32],
    /// AES-256-GCM key authenticating the chip during the handshake.
    pub(crate) k_auth: [u8; 32],
    /// The final transcript hash (associated data for the auth tag).
    pub(crate) h: [u8; 32],
}

impl Drop for Derived
{
    fn drop(&mut self)
    {
        self.k_cmd.zeroize();
        self.k_res.zeroize();
        self.k_auth.zeroize();
        self.h.zeroize();
    }
}

/// Runs the key schedule (transcript hash + three DH + HKDF). No chip auth.
pub(crate) fn derive
(
    ehpriv: &[u8; 32],
    ehpub: &[u8; 32],
    shipriv: &[u8; 32],
    shipub: &[u8; 32],
    stpub: &[u8; 32],
    pkey_index: u8,
    etpub: &[u8; 32],
)
-> Result<Derived, HandshakeError>
{
    // Transcript hash h, six chained SHA-256 steps in protocol order.
    let mut h = crypto::sha256(&[&PROTOCOL_NAME]);
    h = crypto::sha256(&[&h, shipub]);
    h = crypto::sha256(&[&h, stpub]);
    h = crypto::sha256(&[&h, ehpub]);
    h = crypto::sha256(&[&h, &[pkey_index]]);
    h = crypto::sha256(&[&h, etpub]);

    // Key schedule. ck is a 33-byte buffer (tail byte always 0). The first HKDF
    // keys on the 32-byte protocol name. Later HKDFs key on the full 33 bytes.
    // ck and every HKDF output are Zeroizing, so an early `?` return wipes them.
    let mut ck = Zeroizing::new([0u8; 33]);
    let s1 = Zeroizing::new(crypto::x25519(ehpriv, etpub));
    let (o1, _) = crypto::hkdf(&PROTOCOL_NAME, s1.as_slice()).map_err(|_| HandshakeError::Dh)?;
    ck[..32].copy_from_slice(o1.as_slice());

    let s2 = Zeroizing::new(crypto::x25519(shipriv, etpub));
    let (o2, _) = crypto::hkdf(ck.as_slice(), s2.as_slice()).map_err(|_| HandshakeError::Dh)?;
    ck[..32].copy_from_slice(o2.as_slice());

    let s3 = Zeroizing::new(crypto::x25519(ehpriv, stpub));
    let (o3, k_auth) = crypto::hkdf(ck.as_slice(), s3.as_slice()).map_err(|_| HandshakeError::Dh)?;
    ck[..32].copy_from_slice(o3.as_slice());

    let (k_cmd, k_res) = crypto::hkdf(ck.as_slice(), &[]).map_err(|_| HandshakeError::Dh)?;

    Ok(Derived
    {
        k_cmd: *k_cmd,
        k_res: *k_res,
        k_auth: *k_auth,
        h,
    })
}

/// Runs the full handshake: derives keys, then authenticates the chip.
///
/// The chip proves possession of the session via `t_tauth`: an AES-256-GCM tag
/// over an empty plaintext, keyed by kAUTH, nonce all-zero, AAD = transcript
/// hash. On success returns the session keys (both nonces start at 0).
#[expect(
    clippy::too_many_arguments,
    reason = "the Noise KK1 schedule binds distinct public keys and the pairing \
              index. Bundling them into a struct would add a pub type with no \
              other purpose and hide which value feeds which step."
)]
pub(crate) fn run
(
    ehpriv: &[u8; 32],
    ehpub: &[u8; 32],
    shipriv: &[u8; 32],
    shipub: &[u8; 32],
    stpub: &[u8; 32],
    pkey_index: u8,
    etpub: &[u8; 32],
    t_tauth: &[u8; 16],
)
-> Result<SessionKeys, HandshakeError>
{
    let d = derive(ehpriv, ehpub, shipriv, shipub, stpub, pkey_index, etpub)?;
    let iv0 = [0u8; 12];
    let mut empty: [u8; 0] = [];
    crypto::aes256gcm_open(&d.k_auth, &iv0, &d.h, &mut empty, t_tauth)
        .map_err(|_| HandshakeError::BadAuthTag)?;
    Ok(SessionKeys::new(d.k_cmd, d.k_res))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::test_support::vectors::EHPRIV;
    use crate::test_support::vectors::EHPUB;
    use crate::test_support::vectors::ETPUB;
    use crate::test_support::vectors::H_TRANSCRIPT;
    use crate::test_support::vectors::KAUTH;
    use crate::test_support::vectors::KCMD;
    use crate::test_support::vectors::KRES;
    use crate::test_support::vectors::SHIPRIV;
    use crate::test_support::vectors::SHIPUB;
    use crate::test_support::vectors::STPUB;
    use crate::test_support::vectors::T_TAUTH;

    // Golden vectors come from the REAL libtropic (openssl backend) with pinned
    // inputs. See crates/se-driver/tests/oracle/README.md. The Rust schedule
    // MUST reproduce these byte-for-byte.

    #[test]
    fn ephemeral_pub_matches_oracle()
    {
        // The driver derives EHPUB from EHPRIV. It must match the oracle.
        assert_eq!(crypto::x25519_base(&EHPRIV), EHPUB);
    }

    #[test]
    fn key_schedule_matches_golden_kat()
    {
        let d = derive(&EHPRIV, &EHPUB, &SHIPRIV, &SHIPUB, &STPUB, 0, &ETPUB).unwrap();
        assert_eq!(d.h, H_TRANSCRIPT, "transcript hash drift");
        assert_eq!(d.k_cmd, KCMD, "kCMD drift");
        assert_eq!(d.k_res, KRES, "kRES drift");
        assert_eq!(d.k_auth, KAUTH, "kAUTH drift");
    }

    #[test]
    fn run_authenticates_with_valid_tauth()
    {
        let keys = run(&EHPRIV, &EHPUB, &SHIPRIV, &SHIPUB, &STPUB, 0, &ETPUB, &T_TAUTH).unwrap();
        let (k_cmd, k_res) = keys.keys_for_test();
        assert_eq!(k_cmd, KCMD);
        assert_eq!(k_res, KRES);
    }

    #[test]
    fn run_rejects_tampered_tauth()
    {
        let mut bad = T_TAUTH;
        bad[0] ^= 0xFF;
        let r = run(&EHPRIV, &EHPUB, &SHIPRIV, &SHIPUB, &STPUB, 0, &ETPUB, &bad);
        assert_eq!(r.err(), Some(HandshakeError::BadAuthTag));
    }

    #[test]
    fn pkey_index_binds_only_into_the_transcript_hash()
    {
        // The pairing index enters the transcript hash h (and so the auth tag),
        // but NOT the key schedule, which derives from the DH operations and the
        // protocol name. This mirrors libtropic exactly: changing the index
        // changes h (-> t_tauth) while leaving kCMD/kRES untouched.
        let d = derive(&EHPRIV, &EHPUB, &SHIPRIV, &SHIPUB, &STPUB, 1, &ETPUB).unwrap();
        assert_ne!(d.h, H_TRANSCRIPT, "index must change the transcript hash");
        assert_eq!(d.k_cmd, KCMD, "index must not change the key schedule");
        assert_eq!(d.k_res, KRES);
    }
}
