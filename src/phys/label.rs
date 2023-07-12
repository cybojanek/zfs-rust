use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

use crate::checksum::{label_verify, LabelVerifyError};
use crate::phys::{ChecksumTail, UberBlock, UberBlockDecodeError};

////////////////////////////////////////////////////////////////////////////////

/**
 * Blank portion of label.
 *
 * - Bytes: 8192
 *
 * ```text
 * +---------+------+
 * | payload | 8192 |
 * +---------+------+
 * ```
 */
pub struct Blank {
    pub payload: [u8; Blank::PAYLOAD_LENGTH],
}

impl Blank {
    /// Byte length of an encoded [`Blank`].
    pub const LENGTH: usize = 8 * 1024;

    /// Byte offset into a [`Label`].
    pub const OFFSET: usize = 0;

    /// Byte length of the blank payload (8152).
    pub const PAYLOAD_LENGTH: usize = Blank::LENGTH - ChecksumTail::LENGTH;

    /** Decodes a [`Blank`].
     *
     * # Errors.
     *
     * Returns [`BlankDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8; Blank::LENGTH]) -> Result<Blank, BlankDecodeError> {
        Ok(Blank {
            payload: bytes[0..Blank::PAYLOAD_LENGTH].try_into().unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum BlankDecodeError {}

impl fmt::Display for BlankDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BlankDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Boot header portion of label.
 *
 * - Bytes: 8192
 *
 * ```text
 * +---------------+------+
 * |       payload | 8152 |
 * +---------------+------+
 * | checksum tail |   40 |
 * +---------------+------+
 * ```
 */
pub struct BootHeader {
    pub payload: [u8; BootHeader::PAYLOAD_LENGTH],
}

impl BootHeader {
    /// Byte length of an encoded [`BootHeader`].
    pub const LENGTH: usize = 8 * 1024;

    /// Byte offset into a [`Label`].
    pub const OFFSET: usize = Blank::LENGTH;

    /// Byte length of the blank payload (8152).
    pub const PAYLOAD_LENGTH: usize = BootHeader::LENGTH - ChecksumTail::LENGTH;

    /** Decodes a [`BootHeader`].
     *
     * # Errors.
     *
     * Returns [`BootHeaderDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; BootHeader::LENGTH],
        offset: u64,
    ) -> Result<BootHeader, BootHeaderDecodeError> {
        if let Err(e) = label_verify(bytes, offset) {
            return Err(BootHeaderDecodeError::LabelVerifyError { err: e });
        }

        Ok(BootHeader {
            payload: bytes[0..BootHeader::PAYLOAD_LENGTH].try_into().unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum BootHeaderDecodeError {
    /** Label verify error.
     *
     * - `err` - [`LabelVerifyError`]
     */
    LabelVerifyError { err: LabelVerifyError },
}

impl fmt::Display for BootHeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootHeaderDecodeError::LabelVerifyError { err } => {
                write!(f, "Label BootHeader Block verify error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BootHeaderDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            BootHeaderDecodeError::LabelVerifyError { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Boot block portion of label.
 *
 * - Bytes: 3670016 (3584 KiB, 3.5 MiB)
 *
 * ```text
 * +---------+---------+
 * | payload | 3670016 |
 * +---------+---------+
 * ```
 */
pub struct BootBlock {
    pub payload: [u8; BootBlock::PAYLOAD_LENGTH],
}

impl BootBlock {
    /// Byte length of an encoded [`BootBlock`].
    pub const LENGTH: usize = 3584 * 1024;

    /// Byte offset into a block device.
    pub const OFFSET: u64 = (2 * Label::LENGTH) as u64;

    /// Byte length of the blank payload (8152).
    pub const PAYLOAD_LENGTH: usize = BootBlock::LENGTH;

    /** Decodes a [`BootBlock`].
     *
     * # Errors.
     *
     * Returns [`BootBlockDecodeError`] on error.
     */
    pub fn from_bytes(bytes: &[u8; BootBlock::LENGTH]) -> Result<BootBlock, BootBlockDecodeError> {
        Ok(BootBlock {
            payload: bytes[0..BootBlock::PAYLOAD_LENGTH].try_into().unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum BootBlockDecodeError {}

impl fmt::Display for BootBlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "")
    }
}

#[cfg(feature = "std")]
impl error::Error for BootBlockDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * NV Pairs portion of label.
 *
 * - Bytes: 114688 (112 KiB)
 */
pub struct NvPairs {
    pub payload: [u8; NvPairs::PAYLOAD_LENGTH],
}

impl NvPairs {
    /// Byte length of an encoded [`NvPairs`].
    pub const LENGTH: usize = 112 * 1024;

    /// Byte offset into a [`Label`].
    pub const OFFSET: usize = BootHeader::OFFSET + BootHeader::LENGTH;

    /// Byte length of the NV pairs payload (114648).
    pub const PAYLOAD_LENGTH: usize = NvPairs::LENGTH - ChecksumTail::LENGTH;

    /** Decodes a [`NvPairs`].
     *
     * # Errors.
     *
     * Returns [`NvPairsDecodeError`] on error.
     */
    pub fn from_bytes(
        bytes: &[u8; NvPairs::LENGTH],
        offset: u64,
    ) -> Result<NvPairs, NvPairsDecodeError> {
        if let Err(e) = label_verify(bytes, offset) {
            return Err(NvPairsDecodeError::LabelVerifyError { err: e });
        }

        Ok(NvPairs {
            payload: bytes[0..NvPairs::PAYLOAD_LENGTH].try_into().unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum NvPairsDecodeError {
    /** Label verify error.
     *
     * - `err` - [`LabelVerifyError`]
     */
    LabelVerifyError { err: LabelVerifyError },
}

impl fmt::Display for NvPairsDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NvPairsDecodeError::LabelVerifyError { err } => {
                write!(f, "Label NvPairs Block verify error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for NvPairsDecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            NvPairsDecodeError::LabelVerifyError { err } => Some(err),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/**
 * Label of a block device.
 *
 * - Bytes: 262144 (256 KiB)
 *
 * ### Label layout in block device:
 *
 * ```text
 * +----+----+-----------+-----+----+----+
 * | L0 | L1 | BootBlock | ... | L2 | L3 |
 * +----+----+-----------+-----+----+----+
 * ```
 *
 * ### Layout within a label (L0, L1, L2, L3):
 *
 * ```text
 * +----------------+--------+
 * |          Blank |   8192 |
 * +----------------+--------+
 * |     BootHeader |   8192 |
 * +----------------+--------+
 * |        NvPairs | 114688 |
 * +----------------+--------+
 * |   UberBlock[0] |   1024 |
 * +----------------+--------+
 * |            ... |    ... |
 * +----------------+--------+
 * | UberBlock[127] |   1024 |
 * +----------------+--------+
 * ```
 */
pub struct Label {}

impl Label {
    /// Count of [`Label`] in a vdev.
    pub const COUNT: usize = 4;

    /// Count of [`UberBlock`]
    pub const UBER_COUNT: usize = 128;

    /// Byte length of an encoded [`Label`] (256 KiB).
    pub const LENGTH: usize = Blank::LENGTH
        + BootHeader::LENGTH
        + NvPairs::LENGTH
        + (Label::UBER_COUNT * UberBlock::LENGTH);

    /** Get label offsets for a virtual device size. */
    pub fn offsets(vdev_size: u64) -> Result<[u64; 4], LabelOffsetError> {
        let label_length = Label::LENGTH as u64;

        // Check if vdev is too small.
        if vdev_size < label_length * 4 {
            return Err(LabelOffsetError::InvalidSize { size: vdev_size });
        }

        Ok([
            label_length,
            2 * label_length,
            vdev_size - 2 * label_length,
            vdev_size - label_length,
        ])
    }
}

/**
 * Decoded values of a label.
 */
pub struct LabelDecode {
    pub blank: Result<Blank, BlankDecodeError>,
    pub boot_header: Result<BootHeader, BootHeaderDecodeError>,
    pub nv_pairs: Result<NvPairs, NvPairsDecodeError>,
    pub uber_blocks: [Result<UberBlock, UberBlockDecodeError>; Label::UBER_COUNT],
}

impl LabelDecode {
    /** Decodes a [`LabelDecode`].
     *
     * - `offset` into virtual device from [`Label::offsets`] function.
     */
    pub fn from_bytes(data: &[u8; Label::LENGTH], offset: u64) -> LabelDecode {
        // Split data.
        let (blank, rest) = data.split_at(Blank::LENGTH);
        let (boot_header, rest) = rest.split_at(BootHeader::LENGTH);
        let (nv_pairs, uber_blocks) = rest.split_at(NvPairs::LENGTH);

        // Calculate offsets.
        let boot_header_offset = offset + BootHeader::OFFSET as u64;
        let nv_pairs_offset = offset + NvPairs::OFFSET as u64;
        let uber_offset = offset + (Blank::LENGTH + BootHeader::LENGTH + NvPairs::LENGTH) as u64;

        // Decode all components.
        LabelDecode {
            blank: Blank::from_bytes(blank.try_into().unwrap()),
            boot_header: BootHeader::from_bytes(
                boot_header.try_into().unwrap(),
                boot_header_offset,
            ),
            nv_pairs: NvPairs::from_bytes(nv_pairs.try_into().unwrap(), nv_pairs_offset),
            // TODO(cybojanek): Clean this up...is it possible to use a macro?
            //                  Avoid partial initialization.
            //                  Avoid copy/clone.
            uber_blocks: [
                UberBlock::from_bytes(
                    uber_blocks[0 * UberBlock::LENGTH..1 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (0 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[1 * UberBlock::LENGTH..2 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (1 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[2 * UberBlock::LENGTH..3 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (2 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[3 * UberBlock::LENGTH..4 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (3 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[4 * UberBlock::LENGTH..5 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (4 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[5 * UberBlock::LENGTH..6 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (5 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[6 * UberBlock::LENGTH..7 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (6 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[7 * UberBlock::LENGTH..8 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (7 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[8 * UberBlock::LENGTH..9 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (8 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[9 * UberBlock::LENGTH..10 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (9 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[10 * UberBlock::LENGTH..11 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (10 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[11 * UberBlock::LENGTH..12 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (11 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[12 * UberBlock::LENGTH..13 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (12 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[13 * UberBlock::LENGTH..14 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (13 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[14 * UberBlock::LENGTH..15 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (14 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[15 * UberBlock::LENGTH..16 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (15 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[16 * UberBlock::LENGTH..17 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (16 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[17 * UberBlock::LENGTH..18 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (17 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[18 * UberBlock::LENGTH..19 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (18 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[19 * UberBlock::LENGTH..20 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (19 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[20 * UberBlock::LENGTH..21 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (20 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[21 * UberBlock::LENGTH..22 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (21 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[22 * UberBlock::LENGTH..23 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (22 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[23 * UberBlock::LENGTH..24 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (23 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[24 * UberBlock::LENGTH..25 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (24 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[25 * UberBlock::LENGTH..26 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (25 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[26 * UberBlock::LENGTH..27 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (26 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[27 * UberBlock::LENGTH..28 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (27 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[28 * UberBlock::LENGTH..29 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (28 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[29 * UberBlock::LENGTH..30 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (29 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[30 * UberBlock::LENGTH..31 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (30 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[31 * UberBlock::LENGTH..32 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (31 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[32 * UberBlock::LENGTH..33 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (32 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[33 * UberBlock::LENGTH..34 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (33 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[34 * UberBlock::LENGTH..35 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (34 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[35 * UberBlock::LENGTH..36 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (35 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[36 * UberBlock::LENGTH..37 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (36 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[37 * UberBlock::LENGTH..38 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (37 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[38 * UberBlock::LENGTH..39 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (38 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[39 * UberBlock::LENGTH..40 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (39 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[40 * UberBlock::LENGTH..41 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (40 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[41 * UberBlock::LENGTH..42 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (41 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[42 * UberBlock::LENGTH..43 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (42 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[43 * UberBlock::LENGTH..44 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (43 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[44 * UberBlock::LENGTH..45 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (44 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[45 * UberBlock::LENGTH..46 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (45 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[46 * UberBlock::LENGTH..47 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (46 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[47 * UberBlock::LENGTH..48 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (47 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[48 * UberBlock::LENGTH..49 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (48 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[49 * UberBlock::LENGTH..50 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (49 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[50 * UberBlock::LENGTH..51 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (50 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[51 * UberBlock::LENGTH..52 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (51 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[52 * UberBlock::LENGTH..53 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (52 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[53 * UberBlock::LENGTH..54 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (53 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[54 * UberBlock::LENGTH..55 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (54 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[55 * UberBlock::LENGTH..56 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (55 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[56 * UberBlock::LENGTH..57 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (56 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[57 * UberBlock::LENGTH..58 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (57 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[58 * UberBlock::LENGTH..59 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (58 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[59 * UberBlock::LENGTH..60 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (59 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[60 * UberBlock::LENGTH..61 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (60 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[61 * UberBlock::LENGTH..62 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (61 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[62 * UberBlock::LENGTH..63 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (62 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[63 * UberBlock::LENGTH..64 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (63 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[64 * UberBlock::LENGTH..65 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (64 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[65 * UberBlock::LENGTH..66 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (65 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[66 * UberBlock::LENGTH..67 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (66 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[67 * UberBlock::LENGTH..68 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (67 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[68 * UberBlock::LENGTH..69 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (68 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[69 * UberBlock::LENGTH..70 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (69 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[70 * UberBlock::LENGTH..71 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (70 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[71 * UberBlock::LENGTH..72 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (71 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[72 * UberBlock::LENGTH..73 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (72 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[73 * UberBlock::LENGTH..74 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (73 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[74 * UberBlock::LENGTH..75 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (74 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[75 * UberBlock::LENGTH..76 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (75 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[76 * UberBlock::LENGTH..77 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (76 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[77 * UberBlock::LENGTH..78 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (77 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[78 * UberBlock::LENGTH..79 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (78 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[79 * UberBlock::LENGTH..80 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (79 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[80 * UberBlock::LENGTH..81 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (80 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[81 * UberBlock::LENGTH..82 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (81 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[82 * UberBlock::LENGTH..83 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (82 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[83 * UberBlock::LENGTH..84 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (83 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[84 * UberBlock::LENGTH..85 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (84 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[85 * UberBlock::LENGTH..86 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (85 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[86 * UberBlock::LENGTH..87 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (86 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[87 * UberBlock::LENGTH..88 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (87 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[88 * UberBlock::LENGTH..89 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (88 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[89 * UberBlock::LENGTH..90 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (89 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[90 * UberBlock::LENGTH..91 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (90 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[91 * UberBlock::LENGTH..92 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (91 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[92 * UberBlock::LENGTH..93 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (92 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[93 * UberBlock::LENGTH..94 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (93 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[94 * UberBlock::LENGTH..95 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (94 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[95 * UberBlock::LENGTH..96 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (95 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[96 * UberBlock::LENGTH..97 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (96 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[97 * UberBlock::LENGTH..98 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (97 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[98 * UberBlock::LENGTH..99 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (98 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[99 * UberBlock::LENGTH..100 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (99 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[100 * UberBlock::LENGTH..101 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (100 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[101 * UberBlock::LENGTH..102 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (101 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[102 * UberBlock::LENGTH..103 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (102 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[103 * UberBlock::LENGTH..104 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (103 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[104 * UberBlock::LENGTH..105 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (104 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[105 * UberBlock::LENGTH..106 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (105 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[106 * UberBlock::LENGTH..107 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (106 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[107 * UberBlock::LENGTH..108 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (107 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[108 * UberBlock::LENGTH..109 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (108 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[109 * UberBlock::LENGTH..110 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (109 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[110 * UberBlock::LENGTH..111 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (110 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[111 * UberBlock::LENGTH..112 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (111 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[112 * UberBlock::LENGTH..113 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (112 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[113 * UberBlock::LENGTH..114 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (113 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[114 * UberBlock::LENGTH..115 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (114 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[115 * UberBlock::LENGTH..116 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (115 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[116 * UberBlock::LENGTH..117 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (116 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[117 * UberBlock::LENGTH..118 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (117 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[118 * UberBlock::LENGTH..119 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (118 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[119 * UberBlock::LENGTH..120 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (119 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[120 * UberBlock::LENGTH..121 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (120 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[121 * UberBlock::LENGTH..122 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (121 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[122 * UberBlock::LENGTH..123 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (122 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[123 * UberBlock::LENGTH..124 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (123 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[124 * UberBlock::LENGTH..125 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (124 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[125 * UberBlock::LENGTH..126 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (125 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[126 * UberBlock::LENGTH..127 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (126 * UberBlock::LENGTH) as u64,
                ),
                UberBlock::from_bytes(
                    uber_blocks[127 * UberBlock::LENGTH..128 * UberBlock::LENGTH]
                        .try_into()
                        .unwrap(),
                    uber_offset + (127 * UberBlock::LENGTH) as u64,
                ),
            ],
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum LabelOffsetError {
    /** InvalidSize.
     *
     * - `size`: Size.
     */
    InvalidSize { size: u64 },
}

impl fmt::Display for LabelOffsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelOffsetError::InvalidSize { size } => {
                write!(f, "Invalid Label size: {size}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for LabelOffsetError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
