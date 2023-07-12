use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::endian::{DecodeError, Decoder, EncodeError, Encoder};
use crate::phys::{
    BlockPointer, BlockPointerDecodeError, BlockPointerEncodeError, ChecksumType,
    ChecksumTypeError, CompressionType, CompressionTypeError, DmuType, DmuTypeError,
};

////////////////////////////////////////////////////////////////////////////////

/// Is used field of [`Dnode`] in bytes (else in sectors).
const DNODE_FLAG_USED_BYTES: u8 = 1;

/// TODO: What does this mean?
const DNODE_FLAG_USER_USED_ACCOUNTED: u8 = 2;

/// Is a spill block pointer present in [`Dnode`].
const DNODE_FLAG_SPILL_BLOCK_POINTER: u8 = 4;

/// TODO: What does this mean?
const DNODE_FLAG_USER_OBJ_USED_ACCOUNTED: u8 = 8;

/// All known values of flags field of [`Dnode`].
const DNODE_FLAG_ALL: u8 = DNODE_FLAG_USED_BYTES
    | DNODE_FLAG_USER_USED_ACCOUNTED
    | DNODE_FLAG_SPILL_BLOCK_POINTER
    | DNODE_FLAG_USER_OBJ_USED_ACCOUNTED;

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

    pub used_is_bytes: bool,
    pub user_obj_used_accounted: bool,
    pub user_used_accounted: bool,
}

/// Tail of a [`Dnode`].
#[derive(Debug)]
pub enum DnodeTail {
    Zero(DnodeTailZero),
    One(DnodeTailOne),
    Two(DnodeTailTwo),
    Three(DnodeTailThree),
    Spill(DnodeTailSpill),
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
    pub fn from_decoder(decoder: &Decoder) -> Result<Dnode, DnodeDecodeError> {
        ////////////////////////////////
        // Decode DMU type.
        let dmu = DmuType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode indirect block shift.
        let indirect_block_shift = decoder.get_u8()?;

        ////////////////////////////////
        // Decode levels.
        let levels = decoder.get_u8()?;

        ////////////////////////////////
        // Decode number of block pointers.
        let block_pointers_n = decoder.get_u8()?;

        ////////////////////////////////
        // Decode bonus type.
        let bonus_type = DmuType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode checksum.
        let checksum = ChecksumType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode compression.
        let compression = CompressionType::try_from(decoder.get_u8()?)?;

        ////////////////////////////////
        // Decode flags.
        let flags = decoder.get_u8()?;
        if (flags & DNODE_FLAG_ALL) != flags {
            return Err(DnodeDecodeError::InvalidFlags { flags: flags });
        }

        // Check for spill, which only makes sense if block pointers is 1.
        // TODO(cybojanek): Confirm this?
        let is_spill = (flags & DNODE_FLAG_SPILL_BLOCK_POINTER) != 0;
        if is_spill && block_pointers_n != 1 {
            return Err(DnodeDecodeError::InvalidSpillBlockPointerCount {
                count: block_pointers_n,
            });
        }

        ////////////////////////////////
        // Decode block size sectors.
        let data_block_size_sectors = decoder.get_u16()?;

        ////////////////////////////////
        // Decode bonus length.
        let bonus_len = decoder.get_u16()?;

        ////////////////////////////////
        // Decode extra slots.
        let extra_slots = decoder.get_u8()?;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(3)?;

        ////////////////////////////////
        // Decode max block id.
        let max_block_id = decoder.get_u64()?;

        ////////////////////////////////
        // Decode used.
        let used = decoder.get_u64()?;

        ////////////////////////////////
        // Decode padding.
        decoder.skip_zero_padding(32)?;

        ////////////////////////////////
        // Decode tail.
        let max_bonus_len: usize;
        let tail = match block_pointers_n {
            0 => {
                let tail = DnodeTailZero {
                    ptrs: [],
                    bonus: decoder.get_bytes(448)?.try_into().unwrap(),
                };
                max_bonus_len = tail.bonus.len();
                DnodeTail::Zero(tail)
            }
            1 => {
                if is_spill {
                    let tail = DnodeTailSpill {
                        ptrs: [BlockPointer::from_decoder(decoder)?],
                        bonus: decoder.get_bytes(192)?.try_into().unwrap(),
                        spill: BlockPointer::from_decoder(decoder)?,
                    };
                    max_bonus_len = tail.bonus.len();
                    DnodeTail::Spill(tail)
                } else {
                    let tail = DnodeTailOne {
                        ptrs: [BlockPointer::from_decoder(decoder)?],
                        bonus: decoder.get_bytes(320)?.try_into().unwrap(),
                    };
                    max_bonus_len = tail.bonus.len();
                    DnodeTail::One(tail)
                }
            }
            2 => {
                let tail = DnodeTailTwo {
                    ptrs: [
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                    ],
                    bonus: decoder.get_bytes(192)?.try_into().unwrap(),
                };
                max_bonus_len = tail.bonus.len();
                DnodeTail::Two(tail)
            }
            3 => {
                let tail = DnodeTailThree {
                    ptrs: [
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                        BlockPointer::from_decoder(decoder)?,
                    ],
                    bonus: decoder.get_bytes(64)?.try_into().unwrap(),
                };
                max_bonus_len = tail.bonus.len();
                DnodeTail::Three(tail)
            }
            n => return Err(DnodeDecodeError::InvalidBlockPointerCount { count: n }),
        };

        // Check bonus length.
        // NOTE(cybojanek): Safe to cast max_bonus_len as u16, because bonus
        //                  is at most 448 bytes, and bonus_len is a u16.
        if bonus_len > max_bonus_len as u16 {
            return Err(DnodeDecodeError::InvalidBonusLength { length: bonus_len });
        }

        ////////////////////////////////
        // Success.
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

            used_is_bytes: (flags & DNODE_FLAG_USED_BYTES) != 0,
            user_obj_used_accounted: (flags & DNODE_FLAG_USER_OBJ_USED_ACCOUNTED) != 0,
            user_used_accounted: (flags & DNODE_FLAG_USER_USED_ACCOUNTED) != 0,
        })
    }

    /** Encodes a [`Dnode`].
     *
     * # Errors
     *
     * Returns [`DnodeEncodeError`] if there is not enough space, or input is invalid.
     */
    pub fn to_encoder(&self, encoder: &mut Encoder) -> Result<(), DnodeEncodeError> {
        ////////////////////////////////
        // Encode DMU type.
        encoder.put_u8(self.dmu.into())?;

        ////////////////////////////////
        // Encode indirect block shift.
        encoder.put_u8(self.indirect_block_shift)?;

        ////////////////////////////////
        // Encode levels.
        encoder.put_u8(self.levels)?;

        ////////////////////////////////
        // Encode number of block pointers.
        // NOTE(cybojanek): Safe to cast as u8, because length is limited.
        encoder.put_u8(self.pointers().len() as u8)?;

        ////////////////////////////////
        // Encode bonus type.
        encoder.put_u8(self.bonus_type.into())?;

        ////////////////////////////////
        // Encode checksum.
        encoder.put_u8(self.checksum.into())?;

        ////////////////////////////////
        // Encode compression.
        encoder.put_u8(self.compression.into())?;

        ////////////////////////////////
        // Encode flags.
        let flags = (if self.used_is_bytes {
            DNODE_FLAG_USED_BYTES
        } else {
            0
        } | if self.user_used_accounted {
            DNODE_FLAG_USER_USED_ACCOUNTED
        } else {
            0
        } | if self.user_obj_used_accounted {
            DNODE_FLAG_USER_OBJ_USED_ACCOUNTED
        } else {
            0
        } | match &self.tail {
            DnodeTail::Spill(_) => DNODE_FLAG_SPILL_BLOCK_POINTER,
            _ => 0,
        });

        encoder.put_u8(flags)?;

        ////////////////////////////////
        // Encode block size sectors.
        encoder.put_u16(self.data_block_size_sectors)?;

        ////////////////////////////////
        // Encode bonus length.
        // NOTE: Safe to cast, because bonus_capacity is at most 448 bytes.
        if self.bonus_len > self.bonus_capacity().len() as u16 {
            return Err(DnodeEncodeError::InvalidBonusLength {
                length: self.bonus_len,
            });
        }
        encoder.put_u16(self.bonus_len)?;

        ////////////////////////////////
        // Encode extra slots.
        encoder.put_u8(self.extra_slots)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(3)?;

        ////////////////////////////////
        // Encode max block id.
        encoder.put_u64(self.max_block_id)?;

        ////////////////////////////////
        // Encode used.
        encoder.put_u64(self.used)?;

        ////////////////////////////////
        // Encode padding.
        encoder.put_zero_padding(32)?;

        ////////////////////////////////
        // Encode tail.
        for ptr in self.pointers() {
            ptr.to_encoder(encoder)?;
        }
        encoder.put_bytes(self.bonus_capacity())?;

        match &self.tail {
            DnodeTail::Spill(tail) => tail.spill.to_encoder(encoder)?,
            _ => (),
        }

        ////////////////////////////////
        // Success.
        Ok(())
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
            tail: DnodeTail::Zero(DnodeTailZero {
                ptrs: [],
                bonus: [0; 448],
            }),
            used: 0,

            used_is_bytes: false,
            user_obj_used_accounted: false,
            user_used_accounted: false,
        }
    }

    /** Gets capacity bonus slice. */
    pub fn bonus_capacity(&self) -> &[u8] {
        match &self.tail {
            DnodeTail::Zero(tail) => &tail.bonus,
            DnodeTail::One(tail) => &tail.bonus,
            DnodeTail::Two(tail) => &tail.bonus,
            DnodeTail::Three(tail) => &tail.bonus,
            DnodeTail::Spill(tail) => &tail.bonus,
        }
    }

    /** Gets used bonus slice. */
    pub fn bonus_used(&self) -> &[u8] {
        match &self.tail {
            DnodeTail::Zero(tail) => &tail.bonus[0..(self.bonus_len as usize)],
            DnodeTail::One(tail) => &tail.bonus[0..(self.bonus_len as usize)],
            DnodeTail::Two(tail) => &tail.bonus[0..(self.bonus_len as usize)],
            DnodeTail::Three(tail) => &tail.bonus[0..(self.bonus_len as usize)],
            DnodeTail::Spill(tail) => &tail.bonus[0..(self.bonus_len as usize)],
        }
    }

    /** Gets pointers. */
    pub fn pointers(&self) -> &[BlockPointer] {
        match &self.tail {
            DnodeTail::Zero(tail) => &tail.ptrs,
            DnodeTail::One(tail) => &tail.ptrs,
            DnodeTail::Two(tail) => &tail.ptrs,
            DnodeTail::Three(tail) => &tail.ptrs,
            DnodeTail::Spill(tail) => &tail.ptrs,
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

    /** Invalid bonus length.
     *
     * - `length` - Bonus length.
     */
    InvalidBonusLength { length: u16 },

    /** Invlaid flags.
     *
     * - `flags` - Flags.
     */
    InvalidFlags { flags: u8 },

    /** Invlaid spill block pointer count.
     *
     * - `flags` - Flags.
     */
    InvalidSpillBlockPointerCount { count: u8 },
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
            DnodeDecodeError::InvalidFlags { flags } => {
                write!(f, "Dnode decode error: invalid flags {flags}")
            }
            DnodeDecodeError::InvalidSpillBlockPointerCount { count } => {
                write!(
                    f,
                    "Dnode decode error: invalid spill block pointer count {count}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DnodeDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DnodeDecodeError::BlockPointerDecodeError { err } => Some(err),
            DnodeDecodeError::ChecksumTypeError { err } => Some(err),
            DnodeDecodeError::CompressionTypeError { err } => Some(err),
            DnodeDecodeError::DmuTypeError { err } => Some(err),
            DnodeDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DnodeEncodeError {
    /** [`BlockPointer`] encode error.
     *
     * - `err` - [`BlockPointerEncodeError`]
     */
    BlockPointerEncodeError { err: BlockPointerEncodeError },

    /** Endian encode error.
     *
     * - `err` - [`EncodeError`]
     */
    EndianEncodeError { err: EncodeError },

    /** Invalid bonus length.
     *
     * - `length` - Bonus length.
     */
    InvalidBonusLength { length: u16 },
}

impl From<BlockPointerEncodeError> for DnodeEncodeError {
    fn from(value: BlockPointerEncodeError) -> Self {
        DnodeEncodeError::BlockPointerEncodeError { err: value }
    }
}

impl From<EncodeError> for DnodeEncodeError {
    fn from(value: EncodeError) -> Self {
        DnodeEncodeError::EndianEncodeError { err: value }
    }
}

impl fmt::Display for DnodeEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnodeEncodeError::BlockPointerEncodeError { err } => {
                write!(f, "Dnode Block Pointer encode error: {err}")
            }
            DnodeEncodeError::EndianEncodeError { err } => {
                write!(f, "Dnode Endian encode error: {err}")
            }
            DnodeEncodeError::InvalidBonusLength { length } => {
                write!(f, "Dnode encode error: invalid bonus length {length}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DnodeEncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DnodeEncodeError::BlockPointerEncodeError { err } => Some(err),
            DnodeEncodeError::EndianEncodeError { err } => Some(err),
            _ => None,
        }
    }
}
