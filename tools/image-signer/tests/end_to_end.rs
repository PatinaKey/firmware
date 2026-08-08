//! End-to-end test: the signer's output drives the real update machine.
//!
//! A payload is signed with the all-0x01 dev P-256 scalar, then the same bytes are
//! verified by `image_verify::verify_image` and fed through the `fw-update`
//! dual-bank machine, which pins the dev root key.

use fw_update::DEV_ROOT_KEY_TEST_ONLY;
use fw_update::MockFlash;
use fw_update::MockSeCounter;
use fw_update::SE_COUNTER_ORIGIN;
use fw_update::UpdateState;
use fw_update::Updater;
use image_signer::ImageSigner;
use image_signer::SoftwareSigner;
use image_signer::build_signed_image;
use image_verify::ImageVersion;
use image_verify::RootKey;
use image_verify::VerifiedImage;
use image_verify::verify_image;

// The all-0x01 dev private scalar. Its public key equals DEV_ROOT_KEY_TEST_ONLY.
const DEV_KEY: [u8; 32] = [1u8; 32];

fn version() -> ImageVersion
{
    ImageVersion
    {
        major: 1,
        minor: 0,
        revision: 0,
        build: 0,
    }
}

// Concatenates the verified payload segments so a test can compare bytes.
fn collect_payload(verified: &VerifiedImage<'_>) -> Vec<u8>
{
    let mut out = Vec::new();
    for piece in verified.payload_segments()
    {
        out.extend_from_slice(piece);
    }
    out
}

#[test]
fn signed_image_is_accepted_by_verifier_and_update_machine()
{
    let signer = SoftwareSigner::from_key(&DEV_KEY).expect("the dev scalar is valid");
    let payload = b"end to end firmware payload";
    let security_counter = 5u32;

    // 1. The tool mints the image once. This is the only copy used below.
    let image =
        build_signed_image(payload, version(), security_counter, &signer)
            .expect("signing must succeed");

    // 2. The signer's public key must be the dev root key the firmware pins. The tool
    //    and the firmware agree on the encoding (uncompressed SEC1, 65 bytes) and on
    //    the value.
    assert_eq!(signer.public_key(), DEV_ROOT_KEY_TEST_ONLY);

    // 3. image-verify accepts the exact bytes under the dev root key.
    let root = RootKey::from_bytes(DEV_ROOT_KEY_TEST_ONLY)
        .expect("dev root on-curve");
    let segments: [&[u8]; 1] = [&image];
    let verified =
        verify_image(&segments, &root).expect("verify_image must accept");
    assert_eq!(collect_payload(&verified), payload);
    assert_eq!(verified.security_counter(), security_counter);

    // 4. The dual-bank update machine consumes the same bytes through its mock seam,
    //    all the way to a committed and confirmed swap.
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_COUNTER_ORIGIN);
    let mut up = Updater::new(&root, flash, se);

    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image).expect("receive");
    // The machine streamed the exact tool output into its inactive bank, then ran
    // verify off that same bank. Reaching PendingCommit proves the machine accepted
    // the signer's real bytes
    up.verify_and_accept().expect("machine accepts the signed image");
    assert_eq!(up.state(), UpdateState::PendingCommit);

    up.commit().expect("commit");
    assert_eq!(up.state(), UpdateState::Committed);
    up.on_boot().expect("boot");
    up.confirm(security_counter).expect("confirm");
    assert_eq!(up.state(), UpdateState::Confirmed);
}

#[test]
fn an_image_signed_by_a_wrong_key_is_rejected_by_the_machine()
{
    // A non-dev scalar yields a different public key, so the machine pinning the dev
    // root key must reject the tool's output. This pins that the e2e accept above is
    // real, not a path that accepts anything.
    let signer = SoftwareSigner::from_key(&[2u8; 32]).expect("valid scalar");
    let image = build_signed_image(b"evil", version(), 5, &signer)
        .expect("signing succeeds, the tool self-checks under its own key");

    let root = RootKey::from_bytes(DEV_ROOT_KEY_TEST_ONLY)
        .expect("dev root on-curve");
    let flash = MockFlash::new(0);
    let se = MockSeCounter::new(SE_COUNTER_ORIGIN);
    let mut up = Updater::new(&root, flash, se);

    up.begin(image.len()).expect("begin");
    up.receive_chunk(0, &image).expect("receive");
    assert!(
        up.verify_and_accept().is_err(),
        "the machine must reject an image signed by a non-dev key"
    );
    // A rejected image leaves the machine in Idle, never PendingCommit, so no
    // commit can follow.
    assert_eq!(up.state(), UpdateState::Idle);
}
