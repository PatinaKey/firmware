//! Layer 2: request/response framing over the L1 SPI transport.
//!
//! Increment 1 implements frame build/parse and the CRC check. Chunking and
//! reassembly of multi-frame L3 packets arrive in a later increment.

pub(crate) mod frame;
