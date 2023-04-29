use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder};
use crate::phys::{BlockPointer, BlockPointerDecodeError};

////////////////////////////////////////////////////////////////////////////////

/** Checksum tail.
 *
 * - Bytes: 192
 * - C reference: `typedef struct zil_header zil_header_t`
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         claim_txg (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        replay_seq (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                           log (1024)                                                          |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                       claim_blk_seq (64)                                                      |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           flags (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                       claim_lr_seq (64)                                                       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                         padding (192)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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

    /** Decode a [`ZilHeader`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes, or magic is invalid.
     */
    pub fn from_decoder(decoder: &mut Decoder) -> Result<ZilHeader, ZilHeaderDecodeError> {
        let zil_header = ZilHeader {
            claim_txg: decoder.get_u64()?,
            replay_seq: decoder.get_u64()?,
            log: BlockPointer::from_decoder(decoder)?,
            claim_blk_seq: decoder.get_u64()?,
            flags: decoder.get_u64()?,
            claim_lr_seq: decoder.get_u64()?,
        };

        for _ in 0..3 {
            let padding = decoder.get_u64()?;
            if padding != 0 {
                return Err(ZilHeaderDecodeError::NonZeroPadding { padding: padding });
            }
        }

        Ok(zil_header)
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

    /** Non-zero padding.
     *
     * - `padding` - Non-zero padding value.
     */
    NonZeroPadding { padding: u64 },
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
            ZilHeaderDecodeError::NonZeroPadding { padding } => {
                write!(
                    f,
                    "Zil Header decode error: non-zero padding for 0x{padding:016x}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ZilHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ZilHeaderDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
