//! Layer 2: request/response framing over the L1 SPI transport.
//!
//! `frame` builds/parses single frames and checks the CRC. `retry` is the one
//! seam every exchange goes through, so a CRC fault is cured the same way on
//! the plain-L2 and the chunked-L3 path. `transport` drives L1 to send chunked
//! L3 packets and reassemble multi-frame results.

pub(crate) mod frame;
pub(crate) mod retry;
pub(crate) mod transport;
