use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder};
use crate::phys::{
    BlockPointer, BlockPointerDecodeError, ChecksumType, ChecksumTypeError, CompressionType,
    CompressionTypeError, DmuType, DmuTypeError,
};

////////////////////////////////////////////////////////////////////////////////

/** Dnode.
 *
 * - Bytes: 512
 * - C reference: `typedef struct dnode_phys dnode_phys_t`
 *
 * ```text
 * +-------------------------+-----+
 * |                     dmu |   1 |
 * +-------------------------+-----+
 * |    indirect_block_shift |   1 |
 * +-------------------------+-----+
 * |                  levels |   1 |
 * +-------------------------+-----+
 * |        block_pointers_n |   1 |
 * +-------------------------+-----+
 * |              bonus_type |   1 |
 * +-------------------------+-----+
 * |                checksum |   1 |
 * +-------------------------+-----+
 * |             compression |   1 |
 * +-------------------------+-----+
 * |                   flags |   1 |
 * +-------------------------+-----+
 * | data_block_size_sectors |   2 |
 * +-------------------------+-----+
 * |               bonus_len |   2 |
 * +-------------------------+-----+
 * |             extra_slots |   1 |
 * +-------------------------+-----+
 * |                 padding |   3 |
 * +-------------------------+-----+
 * |            max_block_id |   8 |
 * +-------------------------+-----+
 * |                    used |   8 |
 * +-------------------------+-----+
 * |                 padding |  32 |
 * +-------------------------+-----+
 * |                    tail | 448 |
 * +-------------------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct Dnode {
    pub bonus_len: u16,
    pub bonus_type: DmuType,
    pub checksum: ChecksumType,
    pub compression: CompressionType,
    pub data_block_size_sectors: u16,
    pub extra_slots: u8,
    pub dmu: DmuType,
    pub flags: u8,
    pub indirect_block_shift: u8,
    pub levels: u8,
    pub max_block_id: u64,
    pub tail: DnodeTail,
    pub used: u64,
}

#[derive(Debug)]
pub enum DnodeTail {
    Zero { data: DnodeTailZero },
    One { data: DnodeTailOne },
    Two { data: DnodeTailTwo },
    Three { data: DnodeTailThree },
    Spill { data: DnodeTailSpill },
}

/** [`DnodeTail`] with zero block pointers (all bonus).
 *
 * - Bytes: 448
 *
 * ```text
 * +-------+-----+
 * | bonus | 448 |
 * +-------+-----+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailZero {
    pub ptrs: [BlockPointer; 0],
    pub bonus: [u8; 448],
}

/** [`DnodeTail`] with one block pointer (320 bytes of bonus).
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+-----+
 * | block_pointer[0] | 128 |
 * +------------------+-----+
 * |            bonus | 320 |
 * +------------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailOne {
    pub ptrs: [BlockPointer; 1],
    pub bonus: [u8; 320],
}

/** [`DnodeTail`] with two block pointers (192 bytes of bonus).
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+-----+
 * | block_pointer[0] | 128 |
 * +------------------+-----+
 * | block_pointer[1] | 128 |
 * +------------------+-----+
 * |            bonus | 192 |
 * +------------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailTwo {
    pub ptrs: [BlockPointer; 2],
    pub bonus: [u8; 192],
}

/** [`DnodeTail`] with three block pointers (64 bytes of bonus).
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+-----+
 * | block_pointer[0] | 128 |
 * +------------------+-----+
 * | block_pointer[1] | 128 |
 * +------------------+-----+
 * | block_pointer[2] | 128 |
 * +------------------+-----+
 * |            bonus |  64 |
 * +------------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailThree {
    pub ptrs: [BlockPointer; 3],
    pub bonus: [u8; 64],
}

/** [`DnodeTail`] with one block pointer, and one spill (192 bytes of bonus).
 *
 * - Bytes: 448
 *
 * ```text
 * +------------------+-----+
 * | block_pointer[0] | 128 |
 * +------------------+-----+
 * |            bonus | 192 |
 * +------------------+-----+
 * |            spill | 128 |
 * +------------------+-----+
 * ```
 */
#[derive(Debug)]
pub struct DnodeTailSpill {
    pub ptrs: [BlockPointer; 1],
    pub bonus: [u8; 192],
    pub spill: BlockPointer,
}

impl Dnode {
    pub const LENGTH: usize = 512;

    /** Decodes a [`Dnode`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes, or magic is invalid.
     */
    pub fn from_decoder(decoder: &mut Decoder) -> Result<Dnode, DnodeDecodeError> {
        // Decode DMU type.
        let dmu = DmuType::try_from(decoder.get_u8()?)?;

        // Decode values.
        let indirect_block_shift = decoder.get_u8()?;
        let levels = decoder.get_u8()?;
        let block_pointers_n = decoder.get_u8()?;

        // Decode bonus type.
        let bonus_type = DmuType::try_from(decoder.get_u8()?)?;

        // Decode checksum.
        let checksum = ChecksumType::try_from(decoder.get_u8()?)?;

        // Decode compression.
        let compression = CompressionType::try_from(decoder.get_u8()?)?;

        // Decode flags.
        let flags = decoder.get_u8()?;

        // Decode values.
        let data_block_size_sectors = decoder.get_u16()?;
        let bonus_len = decoder.get_u16()?;
        let extra_slots = decoder.get_u8()?;

        // Decode padding.
        decoder.skip_zero_padding(3)?;

        // Decode values.
        let max_block_id = decoder.get_u64()?;
        let used = decoder.get_u64()?;

        // Decode padding.
        decoder.skip_zero_padding(32)?;

        // Decode tail.
        let max_bonus_len: usize;
        let tail = match block_pointers_n {
            3 => {
                let data = DnodeTailThree {
                    ptrs: [
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                    ],
                    bonus: decoder.get_bytes(64)?.try_into().unwrap(),
                };
                max_bonus_len = data.bonus.len();
                DnodeTail::Three { data: data }
            }
            n => return Err(DnodeDecodeError::InvalidBlockPointerCount { count: n }),
        };

        // Check bonus length.
        if bonus_len as usize > max_bonus_len {
            return Err(DnodeDecodeError::InvalidBonusLength { length: bonus_len });
        }

        Ok(Dnode {
            bonus_len: bonus_len,
            bonus_type: bonus_type,
            checksum: checksum,
            compression: compression,
            data_block_size_sectors: data_block_size_sectors,
            dmu: dmu,
            extra_slots: extra_slots,
            flags: flags,
            indirect_block_shift: indirect_block_shift,
            levels: levels,
            max_block_id: max_block_id,
            tail: tail,
            used: used,
        })
    }

    /** An empty [`Dnode`]. */
    pub fn empty() -> Dnode {
        // TODO(cybojanek): Remove this?
        Dnode {
            bonus_len: 0,
            bonus_type: DmuType::None,
            checksum: ChecksumType::Inherit,
            compression: CompressionType::Inherit,
            data_block_size_sectors: 0,
            extra_slots: 0,
            dmu: DmuType::None,
            flags: 0,
            indirect_block_shift: 0,
            levels: 0,
            max_block_id: 0,
            tail: DnodeTail::Zero {
                data: DnodeTailZero {
                    ptrs: [],
                    bonus: [0; 448],
                },
            },
            used: 0,
        }
    }

    /** Get bonus slice. */
    pub fn bonus(&self) -> &[u8] {
        match &self.tail {
            DnodeTail::Zero { data } => &data.bonus[0..(self.bonus_len as usize)],
            DnodeTail::One { data } => &data.bonus[0..(self.bonus_len as usize)],
            DnodeTail::Two { data } => &data.bonus[0..(self.bonus_len as usize)],
            DnodeTail::Three { data } => &data.bonus[0..(self.bonus_len as usize)],
            DnodeTail::Spill { data } => &data.bonus[0..(self.bonus_len as usize)],
        }
    }

    /** Get pointers. */
    pub fn pointers(&self) -> &[BlockPointer] {
        match &self.tail {
            DnodeTail::Zero { data } => &data.ptrs,
            DnodeTail::One { data } => &data.ptrs,
            DnodeTail::Two { data } => &data.ptrs,
            DnodeTail::Three { data } => &data.ptrs,
            DnodeTail::Spill { data } => &data.ptrs,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DnodeDecodeError {
    /** [`BlockPointer`] decode error.
     *
     * - `err` - [`BlockPointerDecodeError`]
     */
    BlockPointerDecodeError { err: BlockPointerDecodeError },

    /** Invalid checksum type.
     *
     * - `err` - ['ChecksumTypeError'].
     */
    ChecksumTypeError { err: ChecksumTypeError },

    /** Invalid compression type.
     *
     * - `err` - ['CompressionTypeError'].
     */
    CompressionTypeError { err: CompressionTypeError },

    /** Invalid DMU type.
     *
     * - `err` - ['DmuTypeError'].
     */
    DmuTypeError { err: DmuTypeError },

    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },

    /** Invalid block pointer count.
     *
     * - `count` - Block pointer count.
     */
    InvalidBlockPointerCount { count: u8 },

    /** Invlaid bonus length.
     *
     * - `length` - Bonus length.
     */
    InvalidBonusLength { length: u16 },
}

impl From<BlockPointerDecodeError> for DnodeDecodeError {
    fn from(value: BlockPointerDecodeError) -> Self {
        DnodeDecodeError::BlockPointerDecodeError { err: value }
    }
}

impl From<ChecksumTypeError> for DnodeDecodeError {
    fn from(value: ChecksumTypeError) -> Self {
        DnodeDecodeError::ChecksumTypeError { err: value }
    }
}

impl From<CompressionTypeError> for DnodeDecodeError {
    fn from(value: CompressionTypeError) -> Self {
        DnodeDecodeError::CompressionTypeError { err: value }
    }
}

impl From<DmuTypeError> for DnodeDecodeError {
    fn from(value: DmuTypeError) -> Self {
        DnodeDecodeError::DmuTypeError { err: value }
    }
}

impl From<DecodeError> for DnodeDecodeError {
    fn from(value: DecodeError) -> Self {
        DnodeDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for DnodeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnodeDecodeError::BlockPointerDecodeError { err } => {
                write!(f, "Dnode Block Pointer decode error: {err}")
            }
            DnodeDecodeError::ChecksumTypeError { err } => {
                write!(f, "Dnode checksum type decode error: {err}")
            }
            DnodeDecodeError::CompressionTypeError { err } => {
                write!(f, "Dnode compression type decode error: {err}")
            }
            DnodeDecodeError::DmuTypeError { err } => {
                write!(f, "Dnode DMU type decode error: {err}")
            }
            DnodeDecodeError::EndianDecodeError { err } => {
                write!(f, "Dnode Endian decode error: {err}")
            }
            DnodeDecodeError::InvalidBlockPointerCount { count } => {
                write!(f, "Dnode decode error: invalid block pointer count {count}")
            }
            DnodeDecodeError::InvalidBonusLength { length } => {
                write!(f, "Dnode decode error: invalid bonus length {length}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DnodeDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DnodeDecodeError::ChecksumTypeError { err } => Some(err),
            DnodeDecodeError::CompressionTypeError { err } => Some(err),
            DnodeDecodeError::DmuTypeError { err } => Some(err),
            DnodeDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
