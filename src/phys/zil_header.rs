use core::fmt;
use core::result::Result;
use core::result::Result::Ok;

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder, EncodeError, Encoder};
use crate::phys::{BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError};

////////////////////////////////////////////////////////////////////////////////

/** Checksum tail.
 *
 * - Bytes: 192
 * - C reference: `typedef struct zil_header zil_header_t`
 *
 * ```text
 * +---------------+-----+
 * |     claim_txg |   8 |
 * +---------------+-----+
 * |    replay_seq |   8 |
 * +---------------+-----+
 * |           log | 128 |
 * +---------------+-----+
 * | claim_blk_seq |   8 |
 * +---------------+-----+
 * |         flags |   8 |
 * +---------------+-----+
 * |  claim_lr_seq |   8 |
 * +---------------+-----+
 * |       padding |  24 |
 * +---------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct ZilHeader {
    pub claim_blk_seq: u64,
    pub claim_lr_seq: u64,
    pub claim_txg: u64,
    pub flags: u64,
    pub log: BlockPointer,
    pub replay_seq: u64,
}

impl ZilHeader {
    /// Byte length of an encoded [`ZilHeader`] (192).
    pub const LENGTH: usize = BlockPointer::LENGTH + 64;

    /** Decodes a [`ZilHeader`].
     *
     * # Errors
     *
     * Returns [`ZilHeaderDecodeError`] on error.
     */
    pub fn from_decoder(decoder: &Decoder) -> Result<ZilHeader, ZilHeaderDecodeError> {
        let zil_header = ZilHeader {
            claim_txg: decoder.get_u64()?,
            replay_seq: decoder.get_u64()?,
            log: BlockPointer::from_decoder(decoder)?,
            claim_blk_seq: decoder.get_u64()?,
            flags: decoder.get_u64()?,
            claim_lr_seq: decoder.get_u64()?,
        };

        decoder.skip_zero_padding(24)?;

        Ok(zil_header)
    }

    /** Encodes a [`ZilHeader`].
     *
     * # Errors
     *
     * Returns [`ZilHeaderEncodeError`] on error.
     */
    pub fn to_encoder(&self, encoder: &mut Encoder) -> Result<(), ZilHeaderEncodeError> {
        encoder.put_u64(self.claim_txg)?;
        encoder.put_u64(self.replay_seq)?;
        self.log.to_encoder(encoder)?;
        encoder.put_u64(self.claim_blk_seq)?;
        encoder.put_u64(self.flags)?;
        encoder.put_u64(self.claim_lr_seq)?;
        encoder.put_zero_padding(24)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ZilHeaderDecodeError {
    /** [`BlockPointer`] decode error.
     *
     * - `err` - [`BlockPointerDecodeError`]
     */
    BlockPointerDecodeError { err: BlockPointerDecodeError },

    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },
}

impl From<BlockPointerDecodeError> for ZilHeaderDecodeError {
    fn from(value: BlockPointerDecodeError) -> Self {
        ZilHeaderDecodeError::BlockPointerDecodeError { err: value }
    }
}

impl From<DecodeError> for ZilHeaderDecodeError {
    fn from(value: DecodeError) -> Self {
        ZilHeaderDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for ZilHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZilHeaderDecodeError::BlockPointerDecodeError { err } => {
                write!(f, "Zil Header Block Pointer decode error: {err}")
            }
            ZilHeaderDecodeError::EndianDecodeError { err } => {
                write!(f, "Zil Header Endian decode error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZilHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZilHeaderDecodeError::BlockPointerDecodeError { err } => Some(err),
            ZilHeaderDecodeError::EndianDecodeError { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum ZilHeaderEncodeError {
    /** [`BlockPointer`] decode error.
     *
     * - `err` - [`BlockPointerEncodeError`]
     */
    BlockPointerEncodeError { err: BlockPointerEncodeError },

    /** Endian decode error.
     *
     * - `err` - [`EncodeError`]
     */
    EndianEncodeError { err: EncodeError },
}

impl From<BlockPointerEncodeError> for ZilHeaderEncodeError {
    fn from(value: BlockPointerEncodeError) -> Self {
        ZilHeaderEncodeError::BlockPointerEncodeError { err: value }
    }
}

impl From<EncodeError> for ZilHeaderEncodeError {
    fn from(value: EncodeError) -> Self {
        ZilHeaderEncodeError::EndianEncodeError { err: value }
    }
}

impl fmt::Display for ZilHeaderEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZilHeaderEncodeError::BlockPointerEncodeError { err } => {
                write!(f, "Zil Header Block Pointer encode error: {err}")
            }
            ZilHeaderEncodeError::EndianEncodeError { err } => {
                write!(f, "Zil Header Endian encode error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZilHeaderEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZilHeaderEncodeError::BlockPointerEncodeError { err } => Some(err),
            ZilHeaderEncodeError::EndianEncodeError { err } => Some(err),
        }
    }
}
