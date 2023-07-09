use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

extern crate num;
extern crate strum;

use crate::endian::{DecodeError, Decoder, Endian};
use crate::phys::{
    ChecksumType, ChecksumTypeError, ChecksumValue, CompressionType, CompressionTypeError, DmuType,
    DmuTypeError, Dva, DvaDecodeError,
};

////////////////////////////////////////////////////////////////////////////////

/** Block pointer.
 *
 * - Bytes: 128
 * - C reference: `typedef struct blkptr blkptr_t`
 */
#[derive(Debug)]
pub enum BlockPointer {
    Embedded { ptr: BlockPointerEmbedded },
    Encrypted { ptr: BlockPointerEncrypted },
    Regular { ptr: BlockPointerRegular },
}

impl BlockPointer {
    /// Byte length of an encoded [`BlockPointer`] (128).
    pub const LENGTH: usize = 3 * Dva::LENGTH + 48 + ChecksumValue::LENGTH;

    /** Decodes a [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or block pointer is malformed.
     */
    pub fn from_decoder(decoder: &mut Decoder) -> Result<BlockPointer, BlockPointerDecodeError> {
        // Decode flags.
        decoder.skip(3 * Dva::LENGTH)?;
        let flags = decoder.get_u64()?;
        decoder.rewind((3 * Dva::LENGTH) + 8)?;

        // Decode encrypted and embedded.
        let embedded = (flags & (0x1 << 39)) != 0;
        let encrypted = (flags & (0x1 << 61)) != 0;

        // Decode based on combination.
        match (embedded, encrypted) {
            (false, false) => Ok(BlockPointer::Regular {
                ptr: BlockPointerRegular::from_decoder(decoder)?,
            }),
            (false, true) => Ok(BlockPointer::Encrypted {
                ptr: BlockPointerEncrypted::from_decoder(decoder)?,
            }),
            (true, false) => Ok(BlockPointer::Embedded {
                ptr: BlockPointerEmbedded::from_decoder(decoder)?,
            }),
            _ => Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded: embedded,
                encrypted: encrypted,
            }),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Embedded block pointer.
 *
 * ```text
 * +-------------------+----+
 * |           payload | 48 |
 * +-------------------+----+
 * |             flags |  8 |
 * +-------------------+----+
 * |           payload | 24 |
 * +-------------------+----+
 * | logical birth txg |  8 |
 * +-------------------+----+
 * |           payload | 40 |
 * +-------------------+----+
 *
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                                                                                               |
 * |                                                      payload[0..48] (384)                                                     |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |b|d|x|level (5)|  dmu type (8) |  emb type (8) |e|   comp (7)  |   phys (7)  |                logical size (25)                |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                     payload[48..72] (192)                                                     |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                     logical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                                                                                               |
 * |                                                     payload[72.112] (320)                                                     |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * b: byte order (0: big, 1: little)
 * d: dedup      (0)
 * x: encryption (0)
 * e: embedded   (1)
 *
 * etype: BlockPointerEmbeddedType
 *  phys: physical size in bytes
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerEmbedded {
    pub compression: CompressionType,
    pub dmu: DmuType,
    pub embedded_type: BlockPointerEmbeddedType,
    pub endian: Endian,
    pub level: u8,
    pub logical_birth_txg: u64,
    pub logical_size: u32,
    pub payload: [u8; BlockPointerEmbedded::MAX_PAYLOAD_LENGTH],
    pub physical_size: u8,
}

/** Checksum type.
 *
 * C reference: `enum bp_embedded_type`
 */
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum BlockPointerEmbeddedType {
    Data = 0,
    Reserved,
    Redacted,
}

impl BlockPointerEmbeddedType {
    /** Converts a [`u8`] to a [`BlockPointerEmbeddedType`], returning `None` if unknown. */
    pub fn from_u8(checksum: u8) -> Option<BlockPointerEmbeddedType> {
        num::FromPrimitive::from_u8(checksum)
    }
}

impl BlockPointerEmbedded {
    pub const MAX_PAYLOAD_LENGTH: usize = 112;

    /** Decodes a [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &mut Decoder,
    ) -> Result<BlockPointerEmbedded, BlockPointerDecodeError> {
        // Decode embedded payload.
        let mut payload = [0; BlockPointerEmbedded::MAX_PAYLOAD_LENGTH];
        (&mut payload[0..48]).copy_from_slice(decoder.get_bytes(48)?);

        // Decode flags.
        let flags = decoder.get_u64()?;

        // Decode embedded payload.
        let payload_1 = decoder.get_bytes(24)?;
        (&mut payload[48..72]).copy_from_slice(payload_1);

        // Decode logical birth transaction group.
        let logical_birth_txg = decoder.get_u64()?;

        // Decode embedded payload.
        let payload_2 = decoder.get_bytes(40)?;
        (&mut payload[72..112]).copy_from_slice(payload_2);

        // Decode encrypted and embedded.
        let embedded = (flags & (1 << 39)) != 0;
        let encrypted = (flags & (1 << 61)) != 0;
        if (embedded, encrypted) != (true, false) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded: embedded,
                encrypted: encrypted,
            });
        }

        // Decode dedup.
        let dedup = (flags & (1 << 62)) != 0;
        if dedup {
            return Err(BlockPointerDecodeError::InvalidDedupValue { dedup: dedup });
        }

        // Decode endian.
        let endian = (flags & (1 << 63)) != 0;
        let endian = match endian {
            false => Endian::Big,
            true => Endian::Little,
        };

        // Decode level.
        let level = ((flags >> 56) & 0x1f) as u8;

        // Decode DMU type.
        let dmu = ((flags >> 48) & 0xff) as u8;
        let dmu = DmuType::try_from(dmu)?;

        // Decode embedded type.
        let embedded_type = ((flags >> 40) & 0xff) as u8;
        let embedded_type = match BlockPointerEmbeddedType::from_u8(embedded_type) {
            Some(v) => v,
            None => {
                return Err(BlockPointerDecodeError::InvalidEmbeddedType {
                    embedded_type: embedded_type,
                })
            }
        };

        // Decode compression.
        let compression = ((flags >> 32) & 0xff) as u8;
        let compression = CompressionType::try_from(compression)?;

        // Decode sizes.
        let logical_size = (flags & 0x1ffffff) as u32;
        let physical_size = ((flags >> 25) & 0x7f) as u8;

        // Check that physical size is within embedded payload length.
        if physical_size as usize > payload.len() {
            return Err(BlockPointerDecodeError::InvalidEmbeddedLength {
                length: physical_size,
            });
        }

        Ok(BlockPointerEmbedded {
            compression: compression,
            dmu: dmu,
            embedded_type: embedded_type,
            endian: endian,
            level: level,
            logical_birth_txg: logical_birth_txg,
            logical_size: logical_size,
            payload: payload,
            physical_size: physical_size,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Encrypted block pointer.
 *
 * ```text
 * +--------------------+----+
 * |             dva[0] | 16 |
 * +--------------------+----+
 * |             dva[1] | 16 |
 * +--------------------+----+
 * |               salt |  8 |
 * +--------------------+----+
 * |                iv1 |  8 |
 * +--------------------+----+
 * |              flags |  8 |
 * +--------------------+----+
 * |            padding | 16 |
 * +--------------------+----+
 * | physical birth txg |  8 |
 * +--------------------+----+
 * |  logical birth txg |  8 |
 * +--------------------+----+
 * | iv2 and fill_count |  8 |
 * +--------------------+----+
 * |        checksum[0] |  8 |
 * +--------------------+----+
 * |        checksum[1] |  8 |
 * +--------------------+----+
 * |             mac[0] |  8 |
 * +--------------------+----+
 * |             mac[1] |  8 |
 * +--------------------+----+
 *
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[0] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[1] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                           salt (64)                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                            iv1 (64)                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |b|d|x|level (5)|  dmu type (8) |  checksum (8) |e|   comp (7)  |       physical size (16)      |       logical_size (16)       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         padding (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    physical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                     logical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                            iv2 (32)                           |                        fill count (32)                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum[0] (64)                                                       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        checksum[1] (64)                                                       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          mac[0] (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          mac[1] (64)                                                          |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * b: byte order (0: big, 1: little)
 * d: dedup      (0 or 1)
 * x: encryption (1)
 * e: embedded   (0)
 *
 * physical size: in 512 byte (sectors - 1)
 *  logical size: in 512 byte (sectors - 1)
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerEncrypted {
    pub checksum_type: ChecksumType,
    pub checksum_value: [u64; 2],
    pub compression: CompressionType,
    pub dedup: bool,
    pub dmu: DmuType,
    pub dvas: [Dva; 2],
    pub endian: Endian,
    pub fill_count: u32,
    pub iv_1: u64,
    pub iv_2: u32,
    pub level: u8,
    pub logical_birth_txg: u64,
    pub logical_size: u16,
    pub mac: [u64; 2],
    pub physical_birth_txg: u64,
    pub physical_size: u16,
    pub salt: u64,
}

impl BlockPointerEncrypted {
    /** Decodes a [`BlockPointer`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &mut Decoder,
    ) -> Result<BlockPointerEncrypted, BlockPointerDecodeError> {
        let dvas = [Dva::from_decoder(decoder)?, Dva::from_decoder(decoder)?];

        // Decode salt and iv.
        let salt = decoder.get_u64()?;
        let iv_1 = decoder.get_u64()?;

        // Decode flags.
        let flags = decoder.get_u64()?;

        // Decode encrypted and embedded.
        let embedded = (flags & (1 << 39)) != 0;
        let encrypted = (flags & (1 << 61)) != 0;
        if (embedded, encrypted) != (false, true) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded: embedded,
                encrypted: encrypted,
            });
        }

        // Decode dedup.
        let dedup = (flags & (1 << 62)) != 0;

        // Decode endian.
        let endian = (flags & (1 << 63)) != 0;
        let endian = match endian {
            false => Endian::Big,
            true => Endian::Little,
        };

        // Decode level.
        let level = ((flags >> 56) & 0x1f) as u8;

        // Decode DMU type.
        let dmu = ((flags >> 48) & 0xff) as u8;
        let dmu = DmuType::try_from(dmu)?;

        // Decode checksum.
        let checksum_type = ((flags >> 40) & 0xff) as u8;
        let checksum_type = ChecksumType::try_from(checksum_type)?;

        // Decode compression.
        let compression = ((flags >> 32) & 0xff) as u8;
        let compression = CompressionType::try_from(compression)?;

        // Decode sizes.
        let logical_size = (flags & 0xffff) as u16;
        let physical_size = ((flags >> 16) & 0xffff) as u16;

        // Decode padding.
        decoder.skip_zero_padding(16)?;

        let physical_birth_txg = decoder.get_u64()?;
        let logical_birth_txg = decoder.get_u64()?;

        let iv_fill = decoder.get_u64()?;
        let iv_2 = (iv_fill >> 32) as u32;
        let fill_count = (iv_fill & 0xffffffff) as u32;
        let checksum_value = [decoder.get_u64()?, decoder.get_u64()?];
        let mac = [decoder.get_u64()?, decoder.get_u64()?];

        Ok(BlockPointerEncrypted {
            checksum_type: checksum_type,
            checksum_value: checksum_value,
            compression: compression,
            dedup: dedup,
            dmu: dmu,
            dvas: dvas,
            endian: endian,
            fill_count: fill_count,
            level: level,
            iv_1: iv_1,
            iv_2: iv_2,
            logical_birth_txg: logical_birth_txg,
            logical_size: logical_size,
            mac: mac,
            physical_birth_txg: physical_birth_txg,
            physical_size: physical_size,
            salt: salt,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

/** Regular block pointer.
 *
 * ```text
 * +--------------------+----+
 * |             dva[0] | 16 |
 * +--------------------+----+
 * |             dva[1] | 16 |
 * +--------------------+----+
 * |             dva[2] | 16 |
 * +--------------------+----+
 * |              flags |  8 |
 * +--------------------+----+
 * |            padding | 16 |
 * +--------------------+----+
 * | physical birth txg |  8 |
 * +--------------------+----+
 * |  logical birth txg |  8 |
 * +--------------------+----+
 * |         fill_count |  8 |
 * +--------------------+----+
 * |           checksum | 32 |
 * +--------------------+----+
 *
 *        6                   5                   4                   3                   2                   1                   0
 *  3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[0] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[1] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                          dva[2] (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |b|d|x|level (5)|  dmu type (8) |  checksum (8) |e|   comp (7)  |       physical size (16)      |       logical_size (16)       |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                         padding (128)                                                         |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    physical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                     logical birth txg (64)                                                    |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                        fill count (64)                                                        |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                                                                                               |
 * |                                                         checksum (256)                                                        |
 * |                                                                                                                               |
 * |                                                                                                                               |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 *
 * b: byte order (0: big, 1: little)
 * d: dedup      (0 or 1)
 * x: encryption (0)
 * e: embedded   (0)
 *
 * physical size: in 512 byte (sectors - 1)
 *  logical size: in 512 byte (sectors - 1)
 * ```
 */
#[derive(Debug)]
pub struct BlockPointerRegular {
    pub checksum_type: ChecksumType,
    pub checksum_value: ChecksumValue,
    pub compression: CompressionType,
    pub dedup: bool,
    pub dmu: DmuType,
    pub dvas: [Dva; 3],
    pub endian: Endian,
    pub fill_count: u64,
    pub level: u8,
    pub logical_birth_txg: u64,
    pub logical_size: u16,
    pub physical_birth_txg: u64,
    pub physical_size: u16,
}

impl BlockPointerRegular {
    /** Decodes a [`BlockPointerRegular`].
     *
     * # Errors
     *
     * Returns [`BlockPointerDecodeError`] if there are not enough bytes,
     * or padding is non-zero.
     */
    pub fn from_decoder(
        decoder: &mut Decoder,
    ) -> Result<BlockPointerRegular, BlockPointerDecodeError> {
        let dvas = [
            Dva::from_decoder(decoder)?,
            Dva::from_decoder(decoder)?,
            Dva::from_decoder(decoder)?,
        ];

        // Decode flags.
        let flags = decoder.get_u64()?;

        // Decode encrypted and embedded.
        let embedded = (flags & (1 << 39)) != 0;
        let encrypted = (flags & (1 << 61)) != 0;
        if (embedded, encrypted) != (false, false) {
            return Err(BlockPointerDecodeError::InvalidBlockPointerType {
                embedded: embedded,
                encrypted: encrypted,
            });
        }

        // Decode dedup.
        let dedup = (flags & (1 << 62)) != 0;

        // Decode endian.
        let endian = (flags & (1 << 63)) != 0;
        let endian = match endian {
            false => Endian::Big,
            true => Endian::Little,
        };

        // Decode level.
        let level = ((flags >> 56) & 0x1f) as u8;

        // Decode DMU type.
        let dmu = ((flags >> 48) & 0xff) as u8;
        let dmu = DmuType::try_from(dmu)?;

        // Decode checksum.
        let checksum_type = ((flags >> 40) & 0xff) as u8;
        let checksum_type = ChecksumType::try_from(checksum_type)?;

        // Decode compression.
        let compression = ((flags >> 32) & 0xff) as u8;
        let compression = CompressionType::try_from(compression)?;

        // Decode sizes.
        let logical_size = (flags & 0xffff) as u16;
        let physical_size = ((flags >> 16) & 0xffff) as u16;

        // Decode padding.
        decoder.skip_zero_padding(16)?;

        let physical_birth_txg = decoder.get_u64()?;
        let logical_birth_txg = decoder.get_u64()?;
        let fill_count = decoder.get_u64()?;
        let checksum_value = ChecksumValue::from_decoder(decoder)?;

        Ok(BlockPointerRegular {
            checksum_type: checksum_type,
            checksum_value: checksum_value,
            compression: compression,
            dedup: dedup,
            dmu: dmu,
            dvas: dvas,
            endian: endian,
            fill_count: fill_count,
            level: level,
            logical_birth_txg: logical_birth_txg,
            logical_size: logical_size,
            physical_birth_txg: physical_birth_txg,
            physical_size: physical_size,
        })
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum BlockPointerDecodeError {
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

    /** DVA decode error.
     *
     * - `err` - [`DvaDecodeError`]
     */
    DvaDecodeError { err: DvaDecodeError },

    /** Endian decode error.
     *
     * - `err` - [`DecodeError`]
     */
    EndianDecodeError { err: DecodeError },

    /** Invalid [`BlockPointer`] type.
     *
     * -  `embedded` - Is embedded.
     * - `encrypted` - Is encrypted.
     */
    InvalidBlockPointerType { embedded: bool, encrypted: bool },

    /** Invalid Dedup value.
     *
     * - `dedup` - Value.
     */
    InvalidDedupValue { dedup: bool },

    /** Invalid embedded length.
     *
     * - `length` - Value.
     */
    InvalidEmbeddedLength { length: u8 },

    /** Invalid embedded type.
     *
     * - `embedded_type` - Value.
     */
    InvalidEmbeddedType { embedded_type: u8 },
}

impl From<ChecksumTypeError> for BlockPointerDecodeError {
    fn from(value: ChecksumTypeError) -> Self {
        BlockPointerDecodeError::ChecksumTypeError { err: value }
    }
}

impl From<CompressionTypeError> for BlockPointerDecodeError {
    fn from(value: CompressionTypeError) -> Self {
        BlockPointerDecodeError::CompressionTypeError { err: value }
    }
}

impl From<DmuTypeError> for BlockPointerDecodeError {
    fn from(value: DmuTypeError) -> Self {
        BlockPointerDecodeError::DmuTypeError { err: value }
    }
}

impl From<DvaDecodeError> for BlockPointerDecodeError {
    fn from(value: DvaDecodeError) -> Self {
        BlockPointerDecodeError::DvaDecodeError { err: value }
    }
}

impl From<DecodeError> for BlockPointerDecodeError {
    fn from(value: DecodeError) -> Self {
        BlockPointerDecodeError::EndianDecodeError { err: value }
    }
}

impl fmt::Display for BlockPointerDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockPointerDecodeError::ChecksumTypeError { err } => {
                write!(f, "BlockPointer checksum type decode error: {err}")
            }
            BlockPointerDecodeError::CompressionTypeError { err } => {
                write!(f, "BlockPointer compression type decode error: {err}")
            }
            BlockPointerDecodeError::DmuTypeError { err } => {
                write!(f, "BlockPointer DMU type decode error: {err}")
            }
            BlockPointerDecodeError::DvaDecodeError { err } => {
                write!(f, "Block Pointer DVA decode error: {err}")
            }
            BlockPointerDecodeError::EndianDecodeError { err } => {
                write!(f, "Block Pointer Endian decode error: {err}")
            }
            BlockPointerDecodeError::InvalidBlockPointerType {
                embedded,
                encrypted,
            } => {
                write!(
                    f,
                    "Block Pointer decode error: embedded: {embedded} encrypted: {encrypted}"
                )
            }
            BlockPointerDecodeError::InvalidDedupValue { dedup } => {
                write!(f, "BlockPointer decode error: invalid dedup value {dedup}")
            }
            BlockPointerDecodeError::InvalidEmbeddedLength { length } => {
                write!(
                    f,
                    "BlockPointer decode error: invalid embdedded length {length}"
                )
            }
            BlockPointerDecodeError::InvalidEmbeddedType { embedded_type } => {
                write!(
                    f,
                    "BlockPointer decode error: invalid embdedded type {embedded_type}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BlockPointerDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BlockPointerDecodeError::ChecksumTypeError { err } => Some(err),
            BlockPointerDecodeError::CompressionTypeError { err } => Some(err),
            BlockPointerDecodeError::DmuTypeError { err } => Some(err),
            BlockPointerDecodeError::EndianDecodeError { err } => Some(err),
            _ => None,
        }
    }
}
