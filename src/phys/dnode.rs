use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder};
use crate::phys::{BlockPointer, BlockPointerDecodeError, ChecksumType, CompressionType, DmuType};

////////////////////////////////////////////////////////////////////////////////

/** Dnode.
 *
 * - Bytes: 512
 * - C reference: `typedef struct dnode_phys dnode_phys_t`
 *
 * ```text
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |    dmu (8)    |  indirect (8) |   levels (8)  | pointers_n (8)| bonus_type (8)|  checksum (8) |compression (8)|   flags (8)   |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |  data_block_size_sectors (16) |         bonus_len (16)        |extra_slots (8)|                  padding (24)                 |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                       max_block_id (64)                                                       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           used (64)                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                         padding (256)                                                         |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                          tail (3584)                                                          |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                      bonus[0..448] (3584)                                                     |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[0] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                      bonus[0..320] (2560)                                                     |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[0] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[1] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                      bonus[0..192] (1536)                                                     |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[0] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[1] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[2] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                       bonus[0..64] (512)                                                      |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                    block_pointer[0] (1024)                                                    |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                      bonus[0..192] (1536)                                                     |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                              ...                                                              |
 * |                                                          spill (1024)                                                         |
 * |                                                              ...                                                              |
 * +-------------------------------------------------------------------------------------------------------------------------------+
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
        let dmu = decoder.get_u8()?;
        let dmu = match DmuType::from_u8(dmu) {
            Some(v) => v,
            None => return Err(DnodeDecodeError::InvalidDmuType { dmu: dmu }),
        };

        // Decode values.
        let indirect_block_shift = decoder.get_u8()?;
        let levels = decoder.get_u8()?;
        let block_pointers_n = decoder.get_u8()?;

        // Decode bonus type.
        let bonus_type = decoder.get_u8()?;
        let bonus_type = match DmuType::from_u8(bonus_type) {
            Some(v) => v,
            None => return Err(DnodeDecodeError::InvalidDmuType { dmu: bonus_type }),
        };

        // Decode checksum.
        let checksum = decoder.get_u8()?;
        let checksum = match ChecksumType::from_u8(checksum) {
            Some(v) => v,
            None => return Err(DnodeDecodeError::InvalidChecksumType { checksum: checksum }),
        };

        // Decode compression.
        let compression = decoder.get_u8()?;
        let compression = match CompressionType::from_u8(compression) {
            Some(v) => v,
            None => {
                return Err(DnodeDecodeError::InvalidCompressionType {
                    compression: compression,
                })
            }
        };

        // Decode flags.
        let flags = decoder.get_u8()?;

        // Decode values.
        let data_block_size_sectors = decoder.get_u16()?;
        let bonus_len = decoder.get_u16()?;
        let extra_slots = decoder.get_u8()?;

        // Decode padding.
        for _ in 0..3 {
            let padding = decoder.get_u8()?;
            if padding != 0 {
                return Err(DnodeDecodeError::NonZeroPadding {
                    padding: padding as u64,
                });
            }
        }

        // Decode values.
        let max_block_id = decoder.get_u64()?;
        let used = decoder.get_u64()?;

        // Decode padding.
        for _ in 0..4 {
            let padding = decoder.get_u64()?;
            if padding != 0 {
                return Err(DnodeDecodeError::NonZeroPadding { padding: padding });
            }
        }

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

    /** Invalid checksum type.
     *
     * - `checksum` - Value.
     */
    InvalidChecksumType { checksum: u8 },

    /** Invalid compression type.
     *
     * - `compression` - Value.
     */
    InvalidCompressionType { compression: u8 },

    /** Invalid DMU type.
     *
     * - `dmu` - Value.
     */
    InvalidDmuType { dmu: u8 },

    /** Non-zero padding.
     *
     * - `padding` - Non-zero padding value.
     */
    NonZeroPadding { padding: u64 },
}

impl From<BlockPointerDecodeError> for DnodeDecodeError {
    fn from(value: BlockPointerDecodeError) -> Self {
        DnodeDecodeError::BlockPointerDecodeError { err: value }
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
            DnodeDecodeError::EndianDecodeError { err } => {
                write!(f, "Dnode Endian decode error: {err}")
            }
            DnodeDecodeError::InvalidBlockPointerCount { count } => {
                write!(f, "Dnode decode error: invalid block pointer count {count}")
            }
            DnodeDecodeError::InvalidBonusLength { length } => {
                write!(f, "Dnode decode error: invalid bonus length {length}")
            }
            DnodeDecodeError::InvalidChecksumType { checksum } => {
                write!(f, "Dnode decode error: invalid checksum type {checksum}")
            }
            DnodeDecodeError::InvalidCompressionType { compression } => {
                write!(
                    f,
                    "Dnode decode error: invalid compression type {compression}"
                )
            }
            DnodeDecodeError::InvalidDmuType { dmu } => {
                write!(f, "Dnode decode error: invalid dmu type {dmu}")
            }
            DnodeDecodeError::NonZeroPadding { padding } => {
                write!(
                    f,
                    "Dnode decode error: non-zero padding for 0x{padding:016x}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DnodeDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DnodeDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
