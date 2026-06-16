//! Protocol identifier enums for the TROPIC01.
//!
//! Byte values come verbatim from the official libtropic headers
//! (v2.0.0 / User API v1.4.0). Each enum carries a checked `TryFrom<u8>`
//! that rejects unknown bytes instead of producing an invalid variant.

/// An unknown protocol byte was received where a known enum was expected.
///
/// Public because it is the `TryFrom<u8>::Error` of the re-exported `L2Status`
/// and `L3Status` enums. Carries the offending byte for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownId(pub u8);

/// L3 encrypted command identifiers (CMD_ID).
///
/// Source: libtropic `src/lt_l3_api_structs.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CmdId
{
    Ping = 0x01,
    PairingKeyWrite = 0x10,
    PairingKeyRead = 0x11,
    PairingKeyInvalidate = 0x12,
    RConfigWrite = 0x20,
    RConfigRead = 0x21,
    RConfigErase = 0x22,
    IConfigWrite = 0x30,
    IConfigRead = 0x31,
    RMemDataWrite = 0x40,
    RMemDataRead = 0x41,
    RMemDataErase = 0x42,
    RandomValueGet = 0x50,
    EccKeyGenerate = 0x60,
    EccKeyStore = 0x61,
    EccKeyRead = 0x62,
    EccKeyErase = 0x63,
    EcdsaSign = 0x70,
    EddsaSign = 0x71,
    McounterInit = 0x80,
    McounterUpdate = 0x81,
    McounterGet = 0x82,
    MacAndDestroy = 0x90,
}

impl TryFrom<u8> for CmdId
{
    type Error = UnknownId;

    fn try_from(v: u8) -> Result<Self, Self::Error>
    {
        let id = match v
        {
            0x01 => CmdId::Ping,
            0x10 => CmdId::PairingKeyWrite,
            0x11 => CmdId::PairingKeyRead,
            0x12 => CmdId::PairingKeyInvalidate,
            0x20 => CmdId::RConfigWrite,
            0x21 => CmdId::RConfigRead,
            0x22 => CmdId::RConfigErase,
            0x30 => CmdId::IConfigWrite,
            0x31 => CmdId::IConfigRead,
            0x40 => CmdId::RMemDataWrite,
            0x41 => CmdId::RMemDataRead,
            0x42 => CmdId::RMemDataErase,
            0x50 => CmdId::RandomValueGet,
            0x60 => CmdId::EccKeyGenerate,
            0x61 => CmdId::EccKeyStore,
            0x62 => CmdId::EccKeyRead,
            0x63 => CmdId::EccKeyErase,
            0x70 => CmdId::EcdsaSign,
            0x71 => CmdId::EddsaSign,
            0x80 => CmdId::McounterInit,
            0x81 => CmdId::McounterUpdate,
            0x82 => CmdId::McounterGet,
            0x90 => CmdId::MacAndDestroy,
            other => return Err(UnknownId(other)),
        };
        Ok(id)
    }
}

/// Get_Info_Req OBJECT_ID values.
///
/// Source: libtropic `src/lt_l2_api_structs.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ObjectId
{
    X509Certificate = 0x00,
    ChipId = 0x01,
    RiscvFwVersion = 0x02,
    SpectFwVersion = 0x04,
    FwBank = 0xB0,
}

impl TryFrom<u8> for ObjectId
{
    type Error = UnknownId;

    fn try_from(v: u8) -> Result<Self, Self::Error>
    {
        let id = match v
        {
            0x00 => ObjectId::X509Certificate,
            0x01 => ObjectId::ChipId,
            0x02 => ObjectId::RiscvFwVersion,
            0x04 => ObjectId::SpectFwVersion,
            0xB0 => ObjectId::FwBank,
            other => return Err(UnknownId(other)),
        };
        Ok(id)
    }
}

/// L2 request identifiers (REQ_ID).
///
/// Source: libtropic `src/lt_l1.h` and `src/lt_l2_api_structs.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum L2ReqId
{
    GetInfo = 0x01,
    Handshake = 0x02,
    EncryptedCmd = 0x04,
    EncryptedSessionAbt = 0x08,
    Resend = 0x10,
    Sleep = 0x20,
    GetLog = 0xA2,
    GetResponse = 0xAA,
    MutableFwUpdateData = 0xB1,
    MutableFwUpdate = 0xB0,
    MutableFwErase = 0xB2,
    Startup = 0xB3,
}

impl TryFrom<u8> for L2ReqId
{
    type Error = UnknownId;

    fn try_from(v: u8) -> Result<Self, Self::Error>
    {
        let id = match v
        {
            0x01 => L2ReqId::GetInfo,
            0x02 => L2ReqId::Handshake,
            0x04 => L2ReqId::EncryptedCmd,
            0x08 => L2ReqId::EncryptedSessionAbt,
            0x10 => L2ReqId::Resend,
            0x20 => L2ReqId::Sleep,
            0xA2 => L2ReqId::GetLog,
            0xAA => L2ReqId::GetResponse,
            0xB1 => L2ReqId::MutableFwUpdateData,
            0xB0 => L2ReqId::MutableFwUpdate,
            0xB2 => L2ReqId::MutableFwErase,
            0xB3 => L2ReqId::Startup,
            other => return Err(UnknownId(other)),
        };
        Ok(id)
    }
}

/// L2 STATUS byte values (the chip's per-frame status).
///
/// Source: libtropic `src/lt_l2_frame_check.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L2Status
{
    /// Request received and accepted.
    RequestOk = 0x01,
    /// Result is ready and OK.
    ResultOk = 0x02,
    /// More request chunks expected.
    RequestCont = 0x03,
    /// More result chunks follow.
    ResultCont = 0x04,
    /// Responses are disabled.
    RespDisabled = 0x78,
    /// Handshake error.
    HskErr = 0x79,
    /// No active session.
    NoSession = 0x7A,
    /// Authentication tag error.
    TagErr = 0x7B,
    /// CRC error on the incoming request.
    CrcErr = 0x7C,
    /// Unknown request identifier.
    UnknownErr = 0x7E,
    /// Generic error.
    GenErr = 0x7F,
    /// No response available.
    NoResp = 0xFF,
}

impl TryFrom<u8> for L2Status
{
    type Error = UnknownId;

    fn try_from(v: u8) -> Result<Self, Self::Error>
    {
        let s = match v
        {
            0x01 => L2Status::RequestOk,
            0x02 => L2Status::ResultOk,
            0x03 => L2Status::RequestCont,
            0x04 => L2Status::ResultCont,
            0x78 => L2Status::RespDisabled,
            0x79 => L2Status::HskErr,
            0x7A => L2Status::NoSession,
            0x7B => L2Status::TagErr,
            0x7C => L2Status::CrcErr,
            0x7E => L2Status::UnknownErr,
            0x7F => L2Status::GenErr,
            0xFF => L2Status::NoResp,
            other => return Err(UnknownId(other)),
        };
        Ok(s)
    }
}

/// L3 RESULT status values (the decrypted command result code).
///
/// Source: libtropic `src/lt_l3_process.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L3Status
{
    /// Command executed successfully.
    Ok = 0xC3,
    /// Generic command failure.
    Fail = 0x3C,
    /// Unauthorized access.
    Unauthorized = 0x01,
    /// Invalid or unsupported command identifier.
    InvalidCmd = 0x02,
    /// The target slot is not empty when expected to be.
    SlotNotEmpty = 0x10,
    /// The target FLASH slot has expired.
    SlotExpired = 0x11,
    /// The key in the selected slot is invalid or corrupted.
    InvalidKey = 0x12,
    /// Update operation failed.
    UpdateErr = 0x13,
    /// The counter is disabled or has failed.
    CounterInvalid = 0x14,
    /// The requested slot is empty.
    SlotEmpty = 0x15,
    /// The slot content is invalidated.
    SlotInvalid = 0x16,
    /// A hardware error occurred during a write operation.
    HardwareFail = 0x17,
}

impl TryFrom<u8> for L3Status
{
    type Error = UnknownId;

    fn try_from(v: u8) -> Result<Self, Self::Error>
    {
        let s = match v
        {
            0xC3 => L3Status::Ok,
            0x3C => L3Status::Fail,
            0x01 => L3Status::Unauthorized,
            0x02 => L3Status::InvalidCmd,
            0x10 => L3Status::SlotNotEmpty,
            0x11 => L3Status::SlotExpired,
            0x12 => L3Status::InvalidKey,
            0x13 => L3Status::UpdateErr,
            0x14 => L3Status::CounterInvalid,
            0x15 => L3Status::SlotEmpty,
            0x16 => L3Status::SlotInvalid,
            0x17 => L3Status::HardwareFail,
            other => return Err(UnknownId(other)),
        };
        Ok(s)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn cmd_id_round_trips_known_values()
    {
        for v in [0x01u8, 0x10, 0x50, 0x60, 0x70, 0x71, 0x90]
        {
            let id = CmdId::try_from(v).unwrap();
            assert_eq!(id as u8, v);
        }
    }

    #[test]
    fn cmd_id_rejects_unknown()
    {
        assert_eq!(CmdId::try_from(0x00), Err(UnknownId(0x00)));
        assert_eq!(CmdId::try_from(0xFF), Err(UnknownId(0xFF)));
    }

    #[test]
    fn object_id_round_trips()
    {
        for v in [0x00u8, 0x01, 0x02, 0x04, 0xB0]
        {
            assert_eq!(ObjectId::try_from(v).unwrap() as u8, v);
        }
        assert_eq!(ObjectId::try_from(0x03), Err(UnknownId(0x03)));
    }

    #[test]
    fn l2_req_id_round_trips()
    {
        for v in [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0xA2, 0xAA, 0xB0, 0xB1, 0xB2, 0xB3]
        {
            assert_eq!(L2ReqId::try_from(v).unwrap() as u8, v);
        }
        assert_eq!(L2ReqId::try_from(0x55), Err(UnknownId(0x55)));
    }

    #[test]
    fn l2_status_round_trips_and_rejects()
    {
        for v in [0x01u8, 0x02, 0x03, 0x04, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7E, 0x7F, 0xFF]
        {
            assert_eq!(L2Status::try_from(v).unwrap() as u8, v);
        }
        assert_eq!(L2Status::try_from(0x00), Err(UnknownId(0x00)));
        assert_eq!(L2Status::try_from(0x7D), Err(UnknownId(0x7D)));
    }

    #[test]
    fn l3_status_round_trips_and_rejects()
    {
        for v in [0xC3u8, 0x3C, 0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]
        {
            assert_eq!(L3Status::try_from(v).unwrap() as u8, v);
        }
        assert_eq!(L3Status::try_from(0x00), Err(UnknownId(0x00)));
        assert_eq!(L3Status::try_from(0xFF), Err(UnknownId(0xFF)));
    }
}
