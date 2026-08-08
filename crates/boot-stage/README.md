# boot-stage

Immutable first-stage boot code for the A/B update model. Runs from pages 2-8 of
whichever bank the hardware boots (SECBOOTADD0 = 0x0C004000, selected by
SWAP_BANK). It reads the image DESCRIPTOR on page 9 of the active bank (the signed
header and signature), verifies the four logical segments with the P-256 verifier
(header, secure payload, non-secure payload, signature), then jumps to the secure
app link origin 0x0C014000, and drives commit/revert.

The boot DECISION is a state machine (`decision.rs`) over the persistent
state (running bank, pending record, NVCNT, image health). It is proven
exhaustively on the host, including a power-cut census at every persistent
mutation boundary. The silicon glue (the real flash driver port, the register
reads, the secure-to-secure jump) is thin and target-only (`entry.rs`, `real.rs`).
The anti-rollback NVCNT bump is done last and is mutually exclusive with a revert.

The FLASH origin/length here MUST agree with the layout table:

    pages 0-1   0x0C000000  16K  boot metadata (physical Bank 1 only)
    pages 2-8   0x0C004000  56K  boot stage (this crate, IMMUTABLE)
    page  9     0x0C012000  8K   image descriptor (header [0:24], signature [24:88])
    pages 10-19 0x0C014000  80K  secure app + NSC veneer
    pages 20-31 0x08028000  96K  non-secure app
