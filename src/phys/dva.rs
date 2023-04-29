use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder};

////////////////////////////////////////////////////////////////////////////////

/// Mask for unused padding.
const PADDING_MASK: u64 = 0xff00000000000000;

/// Mask for vdev field.
const VDEV_MASK: u64 = 0x00ffffff00000000;

/// Shift for vdev field.
const VDEV_SHIFT: usize = 32;

/// Mask for grid field.
const GRID_MASK: u64 = 0x00000000ff000000;

/// Shift for grid field.
const GRID_SHIFT: usize = 24;

/// Mask for asize field.
const ASIZE_MASK: u64 = 0x0000000000ffffff;

////////////////////////////////////////////////////////////////////////////////

/// Mask for gang bit.
const GANG_MASK: u64 = 0x8000000000000000;

/// Mask for offset field.
const OFFSET_MASK: u64 = 0x7fffffffffffffff;

////////////////////////////////////////////////////////////////////////////////

/** DVA (Data Virtual Address).
 *
 * - Bytes: 16
 * - C reference: `typedef struct dva dva_t`
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |  padding (8)  |                   vdev (24)                   |    grid (8)   |                   asize (24)                  |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |g|                                                         offset (63)                                                         |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * g: Gang
 * ```
 */
#[derive(Debug)]
pub struct Dva {
    pub vdev: u32,
    pub grid: u8,
    pub asize: u32,
    pub offset: u64,
    pub is_gang: bool,
}

impl Dva {
    /// Byte length of an encoded [`Dva`].
    pub const LENGTH: usize = 16;

    /** Decode a [`Dva`].
     *
     * # Errors
     *
     * Returns [`DvaDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(decoder: &mut Decoder) -> Result<Dva, DvaDecodeError> {
        // Decode values.
        let a = decoder.get_u64()?;
        let b = decoder.get_u64()?;

        // Check for non-zero padding.
        let padding = a & PADDING_MASK;
        if padding != 0 {
            return Err(DvaDecodeError::NonZeroPadding { padding: padding });
        }

        Ok(Dva {
            vdev: ((a & VDEV_MASK) >> VDEV_SHIFT) as u32,
            grid: ((a & GRID_MASK) >> GRID_SHIFT) as u8,
            asize: (a & ASIZE_MASK) as u32,
            offset: b & OFFSET_MASK,
            is_gang: (b & GANG_MASK) != 0,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DvaDecodeError {
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

impl From<DecodeError> for DvaDecodeError {
    fn from(value: DecodeError) -> Self {
        DvaDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for DvaDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DvaDecodeError::EndianDecodeError { err } => {
                write!(f, "DVA Endian decode error: {err}")
            }
            DvaDecodeError::NonZeroPadding { padding } => {
                write!(f, "DVA decode error: non-zero padding for 0x{padding:016x}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DvaDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DvaDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
