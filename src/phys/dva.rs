use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder, EncodeError, Encoder};
use crate::phys::sector;
use crate::phys::{BootBlock, Label};

////////////////////////////////////////////////////////////////////////////////

/// Mask for unused padding.
const PADDING_MASK: u64 = 0xff00000000000000;

/// Mask for vdev field.
const VDEV_MASK_SHIFTED: u64 = 0x0000000000ffffff;

/// Shift for vdev field.
const VDEV_SHIFT: usize = 32;

/// Mask for grid field.
const GRID_MASK_SHIFTED: u64 = 0x00000000000000ff;

/// Shift for grid field.
const GRID_SHIFT: usize = 24;

/// Shift for asize field.
const ASIZE_SHIFT: usize = 0;

/// Mask for asize field.
const ASIZE_MASK_SHIFTED: u64 = 0x0000000000ffffff;

////////////////////////////////////////////////////////////////////////////////

/// Mask for gang bit.
const GANG_MASK: u64 = 0x8000000000000000;

/// Mask for offset field.
const OFFSET_MASK: u64 = 0x7fffffffffffffff;

/// Base offset for DVA calculations, in bytes.
const BASE_OFFSET_BYTES: u64 = (2 * Label::LENGTH + BootBlock::LENGTH) as u64;

/// Base offset for DVA calculation, in sectors.
const BASE_OFFSET_SECTORS: u64 = BASE_OFFSET_BYTES >> sector::shift!();

////////////////////////////////////////////////////////////////////////////////

/** DVA (Data Virtual Address).
 *
 * - Bytes: 16
 * - C reference: `typedef struct dva dva_t`
 *
 * ```text
 * +--------+---+
 * |  flags | 8 |
 * +--------+---+
 * | offset | 8 |
 * +--------+---+
 *
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

    /** Decodes a [`Dva`].
     *
     * # Errors
     *
     * Returns [`DvaDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(decoder: &Decoder) -> Result<Dva, DvaDecodeError> {
        ////////////////////////////////
        // Decode values.
        let a = decoder.get_u64()?;
        let b = decoder.get_u64()?;

        ////////////////////////////////
        // Check for empty DVA.
        if a == 0 && b == 0 {
            return Ok(Dva {
                vdev: 0,
                grid: 0,
                asize: 0,
                offset: 0,
                is_gang: false,
            });
        }

        ////////////////////////////////
        // Check for non-zero padding.
        let padding = a & PADDING_MASK;
        if padding != 0 {
            return Err(DvaDecodeError::NonZeroPadding { padding: padding });
        }

        ////////////////////////////////
        // Success!
        Ok(Dva {
            vdev: ((a >> VDEV_SHIFT) & VDEV_MASK_SHIFTED) as u32,
            grid: ((a >> GRID_SHIFT) & GRID_MASK_SHIFTED) as u8,
            asize: ((a >> ASIZE_SHIFT) & ASIZE_MASK_SHIFTED) as u32,
            offset: b & OFFSET_MASK,
            is_gang: (b & GANG_MASK) != 0,
        })
    }

    /** Encodes a [`Dva`].
     *
     * # Errors
     *
     * Returns [`DvaEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(&self, encoder: &mut Encoder) -> Result<(), DvaEncodeError> {
        ////////////////////////////////
        // Upcast for checks.
        let vdev = self.vdev as u64;
        let grid = self.grid as u64;
        let asize = self.asize as u64;

        ////////////////////////////////
        // Check values.
        if asize > ASIZE_MASK_SHIFTED {
            return Err(DvaEncodeError::InvalidAsize { asize: self.asize });
        }

        if vdev > VDEV_MASK_SHIFTED {
            return Err(DvaEncodeError::InvalidVdev { vdev: self.vdev });
        }

        if self.offset > OFFSET_MASK {
            return Err(DvaEncodeError::InvalidOffset {
                offset: self.offset,
            });
        }

        ////////////////////////////////
        // Encode.
        let a = (vdev << VDEV_SHIFT) | (grid << GRID_SHIFT) | (asize << ASIZE_SHIFT);
        let b = (if self.is_gang { GANG_MASK } else { 0 } | self.offset);

        encoder.put_u64(a)?;
        encoder.put_u64(b)?;

        Ok(())
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

    /** Invalid offset error.
     *
     * - `offset`
     */
    InvalidOffset { offset: u64 },

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
            DvaDecodeError::InvalidOffset { offset } => {
                write!(f, "DVA decode error: invalid offset 0x{offset:016x}")
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

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DvaEncodeError {
    /** Endian encode error.
     *
     * - `err` - [`EncodeError`]
     */
    EndianEncodeError { err: EncodeError },

    /** Invalid asize error.
     *
     * - `asize`
     */
    InvalidAsize { asize: u32 },

    /** Invalid offset error.
     *
     * - `offset`
     */
    InvalidOffset { offset: u64 },

    /** Invalid vdev error.
     *
     * - `vdev`
     */
    InvalidVdev { vdev: u32 },
}

impl From<EncodeError> for DvaEncodeError {
    fn from(value: EncodeError) -> Self {
        DvaEncodeError::EndianEncodeError { err: value }
    }
}

impl fmt::Display for DvaEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DvaEncodeError::EndianEncodeError { err } => {
                write!(f, "DVA Endian encode error: {err}")
            }
            DvaEncodeError::InvalidAsize { asize } => {
                write!(f, "DVA encode error: invalid asize 0x{asize:08x}")
            }
            DvaEncodeError::InvalidOffset { offset } => {
                write!(f, "DVA encode error: invalid offset 0x{offset:016x}")
            }
            DvaEncodeError::InvalidVdev { vdev } => {
                write!(f, "DVA encode error: invalid vdev 0x{vdev:08x}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DvaEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DvaEncodeError::EndianEncodeError { err } => Some(err),
            _ => None,
        }
    }
}
