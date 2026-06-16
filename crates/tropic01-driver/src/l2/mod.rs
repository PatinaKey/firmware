//! Layer 2: request/response framing over the L1 SPI transport.
//!
//! `frame` builds/parses single frames and checks the CRC. `transport` drives
//! L1 to send chunked L3 packets and reassemble multi-frame results.

pub(crate) mod frame;
pub(crate) mod transport;
