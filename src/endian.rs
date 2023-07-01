/*! A binary endian decoder and encoder.
 *
 * - [`Decoder`] uses an internal [`Cell`] field for the `offset` field
 *   in order to implement a split borrow.
 */
use core::cell::Cell;
use core::fmt;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

extern crate strum;

////////////////////////////////////////////////////////////////////////////////

/** Endian. */
#[derive(Copy, Clone, Debug, strum::Display)]
pub enum Endian {
    Big,
    Little,
}

/** Native encoding. */
#[cfg(target_endian = "big")]
pub const NATIVE: Endian = Endian::Big;

/** Native encoding. */
#[cfg(target_endian = "little")]
pub const NATIVE: Endian = Endian::Little;

/** Swapped encoding (opposite of [`NATIVE`]). */
#[cfg(target_endian = "big")]
pub const SWAP: Endian = Endian::Little;

/** Swapped encoding (opposite of [`NATIVE`]). */
#[cfg(target_endian = "little")]
pub const SWAP: Endian = Endian::Big;

////////////////////////////////////////////////////////////////////////////////

type U16Decoder = fn(bytes: [u8; 2]) -> u16;
type U32Decoder = fn(bytes: [u8; 4]) -> u32;
type U64Decoder = fn(bytes: [u8; 8]) -> u64;

/** Decoder for an [`Endian`] type. */
struct EndianDecoder {
    endian: Endian,
    get_u16: U16Decoder,
    get_u32: U32Decoder,
    get_u64: U64Decoder,
}

/** [`Endian::Big`] decoder. */
const BIG_ENDIAN_DECODER: EndianDecoder = EndianDecoder {
    endian: Endian::Big,
    get_u16: u16::from_be_bytes,
    get_u32: u32::from_be_bytes,
    get_u64: u64::from_be_bytes,
};

/** [`Endian::Little`] decoder. */
const LITTLE_ENDIAN_DECODER: EndianDecoder = EndianDecoder {
    endian: Endian::Little,
    get_u16: u16::from_le_bytes,
    get_u32: u32::from_le_bytes,
    get_u64: u64::from_le_bytes,
};

/** A binary decoder.
 */
pub struct Decoder<'a> {
    data: &'a [u8],
    offset: Cell<usize>,
    decoder: EndianDecoder,
}

impl fmt::Debug for Decoder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("Decoder")
            .field("length", &self.data.len())
            .field("offset", &self.offset.get())
            .field("endian", &self.decoder.endian)
            .finish()
    }
}

impl Decoder<'_> {
    /** Initializes a [`Decoder`] based on the supplied [`Endian`] value.
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u64().unwrap(), 0x123456789abcdef0);
     * assert_eq!(decoder.get_u64().unwrap(), 0x1122334455667788);
     *
     * // DecodeError::EndOfInput
     * assert!(decoder.get_u64().is_err());
     * ```
     */
    pub fn from_bytes(data: &[u8], endian: Endian) -> Decoder {
        Decoder {
            data: data,
            offset: Cell::new(0),
            decoder: match endian {
                Endian::Big => BIG_ENDIAN_DECODER,
                Endian::Little => LITTLE_ENDIAN_DECODER,
            },
        }
    }

    /** Initializes a [`Decoder`] based on the expected magic value.
     *
     * Picks endian to match magic value.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if array is too short or magic does not match.
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::Decoder;
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_u64_magic(data, 0x123456789abcdef0).unwrap();
     *
     * // Initial status.
     * assert_eq!(decoder.capacity(), data.len());
     * assert_eq!(decoder.len(), 8);
     * assert_eq!(decoder.is_empty(), false);
     *
     * // Get u64.
     * assert_eq!(decoder.get_u64().unwrap(), 0x1122334455667788);
     *
     * // Status after decoding.
     * assert_eq!(decoder.capacity(), data.len());
     * assert_eq!(decoder.len(), 0);
     * assert_eq!(decoder.is_empty(), true);
     *
     * // Some bytes (litle endian).
     * let data = &[
     *     0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
     *     0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_u64_magic(data, 0x123456789abcdef0).unwrap();
     * assert_eq!(decoder.get_u64().unwrap(), 0x1122334455667788);
     * ```
     *
     * Magic mismatch
     *
     * ```
     * use zfs::endian::Decoder;
     *
     * // Some bytes (big endian).
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_u64_magic(data, 0x123456789abcdef0);
     * assert!(decoder.is_err());
     * ```
     *
     * Slice too short:
     *
     * ```
     * use zfs::endian::Decoder;
     *
     * // Not enough bytes for magic.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
     * let decoder = Decoder::from_u64_magic(data, 0x123456789abcdef0);
     * assert!(decoder.is_err());
     * ```
     */
    pub fn from_u64_magic(data: &[u8], magic: u64) -> Result<Decoder, DecodeError> {
        // Initialize decoder assuming little endian.
        let mut decoder = Decoder::from_bytes(data, Endian::Little);

        // Try to get the magic.
        let data_magic = decoder.get_u64()?;

        // If it doesn't match, then swap bytes and compare again.
        if data_magic != magic {
            let data_magic = data_magic.swap_bytes();
            if data_magic != magic {
                // It still doesn't match.
                return Err(DecodeError::InvalidMagic {
                    expected: magic,
                    actual: data_magic.to_le_bytes(),
                });
            }

            // Update decoder to big endian.
            decoder.decoder = BIG_ENDIAN_DECODER;
        }

        Ok(decoder)
    }

    /** Checks if there are enough bytes to decode from the data slice.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     */
    fn check_need(&self, count: usize) -> Result<(), DecodeError> {
        if self.len() >= count {
            Ok(())
        } else {
            Err(DecodeError::EndOfInput {
                offset: self.offset.get(),
                length: self.data.len(),
                count: count,
            })
        }
    }

    /** Returns the source data length.
     *
     * Remains unchanged while decoding values.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     * assert_eq!(decoder.capacity(), data.len());
     *
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.capacity(), data.len());
     *
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.capacity(), data.len());
     * ```
     */
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /** Returns the [`Endian`] of the decoder.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get endian.
     * assert!(matches!(decoder.endian(), Endian::Big));
     * ```
     */
    pub fn endian(&self) -> Endian {
        self.decoder.endian
    }

    /** Returns true if there are no more bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get values.
     * while !decoder.is_empty() {
     *     assert_eq!(decoder.get_u32().unwrap(), 1);
     * }
     * ```
     */
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /** Returns length of bytes remaining to be decoded.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     * assert_eq!(decoder.len(), 16);
     *
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.len(), 8);
     *
     * decoder.get_u64().unwrap();
     * assert_eq!(decoder.len(), 0);
     * ```
     */
    pub fn len(&self) -> usize {
        // Gracefully handle offset errors, and just return 0.
        match self.data.len().checked_sub(self.offset.get()) {
            Some(v) => v,
            None => 0,
        }
    }

    /// Resets the decoder to the start of the data.
    pub fn reset(&self) {
        self.offset.set(0);
    }

    /** Skips the next `count` bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to skip.
     */
    pub fn skip(&self, count: usize) -> Result<(), DecodeError> {
        self.check_need(count)?;
        self.offset.set(self.offset.get() + count);
        Ok(())
    }

    /** Skips the next `count` bytes as zero padding.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to skip, or the
     * bytes are non-zero.
     */
    pub fn skip_zero_padding(&self, count: usize) -> Result<(), DecodeError> {
        self.check_need(count)?;

        let offset = self.offset.get();
        let mut x = 0;

        for idx in offset..offset + count {
            x |= self.data[idx];
        }

        if x != 0 {
            return Err(DecodeError::NonZeroPadding {});
        }

        self.offset.set(offset + count);

        Ok(())
    }

    /** Rewinds `count` bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to rewind.
     */
    pub fn rewind(&self, count: usize) -> Result<(), DecodeError> {
        let offset = self.offset.get();
        if count > offset {
            return Err(DecodeError::RewindPastStart {
                offset: offset,
                count: count,
            });
        }
        self.offset.set(offset - count);
        Ok(())
    }

    /** Returns 2 bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     */
    pub fn get_2_bytes(&self) -> Result<[u8; 2], DecodeError> {
        self.check_need(2)?;

        let start = self.offset.get();
        let end = start + 2;

        self.offset.set(end);

        Ok(<[u8; 2]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns 4 bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     */
    pub fn get_4_bytes(&self) -> Result<[u8; 4], DecodeError> {
        self.check_need(4)?;

        let start = self.offset.get();
        let end = start + 4;

        self.offset.set(end);

        Ok(<[u8; 4]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns 8 bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     */
    pub fn get_8_bytes(&self) -> Result<[u8; 8], DecodeError> {
        self.check_need(8)?;

        let start = self.offset.get();
        let end = start + 8;

        self.offset.set(end);

        Ok(<[u8; 8]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Decodes bytes.
     *
     * [`Endian`] does not matter for order of decoded bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get bytes.
     * let a = decoder.get_bytes(2).unwrap();
     * let b = decoder.get_bytes(1).unwrap();
     * assert_eq!(a, [0xf2, 0x34]);
     * assert_eq!(b, [0x56]);
     *
     * // Error end of input.
     * assert!(decoder.get_bytes(2).is_err());
     */
    pub fn get_bytes(&self, length: usize) -> Result<&[u8], DecodeError> {
        // Check bounds for length.
        self.check_need(length)?;

        // Start and end of bytes.
        let start = self.offset.get();
        let end = start + length;

        // Consume bytes.
        let value = &self.data[start..end];
        self.offset.set(end);

        // Return bytes.
        Ok(value)
    }

    /** Decodes a [`u8`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u8().unwrap(), 0xf2);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u8().is_err());
     * ```
     */
    pub fn get_u8(&self) -> Result<u8, DecodeError> {
        self.check_need(1)?;

        let offset = self.offset.get();
        let value = self.data[offset];
        self.offset.set(offset + 1);

        Ok(value)
    }

    /** Decodes a [`u16`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u16().unwrap(), 0xf234);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u16().is_err());
     * ```
     */
    pub fn get_u16(&self) -> Result<u16, DecodeError> {
        Ok((self.decoder.get_u16)(self.get_2_bytes()?))
    }

    /** Decodes a [`u32`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u32().unwrap(), 0xf2345678);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u32().is_err());
     * ```
     */
    pub fn get_u32(&self) -> Result<u32, DecodeError> {
        Ok((self.decoder.get_u32)(self.get_4_bytes()?))
    }

    /** Decodes a [`u64`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Get values.
     * assert_eq!(decoder.get_u64().unwrap(), 0xf23456789abcdef0);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::endian::{Decoder, Endian};
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data, Endian::Big);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u64().is_err());
     * ```
     */
    pub fn get_u64(&self) -> Result<u64, DecodeError> {
        Ok((self.decoder.get_u64)(self.get_8_bytes()?))
    }
}

////////////////////////////////////////////////////////////////////////////////

type U16Encoder = fn(value: u16) -> [u8; 2];
type U32Encoder = fn(value: u32) -> [u8; 4];
type U64Encoder = fn(value: u64) -> [u8; 8];

/** Encoder for an [`Endian`] type. */
struct EndianEncoder {
    endian: Endian,
    put_u16: U16Encoder,
    put_u32: U32Encoder,
    put_u64: U64Encoder,
}

/** [`Endian::Big`] encoder. */
const BIG_ENDIAN_ENCODER: EndianEncoder = EndianEncoder {
    endian: Endian::Big,
    put_u16: u16::to_be_bytes,
    put_u32: u32::to_be_bytes,
    put_u64: u64::to_be_bytes,
};

/** [`Endian::Little`] encoder. */
const LITTLE_ENDIAN_ENCODER: EndianEncoder = EndianEncoder {
    endian: Endian::Little,
    put_u16: u16::to_le_bytes,
    put_u32: u32::to_le_bytes,
    put_u64: u64::to_le_bytes,
};

/** A binary encoder.
 */
pub struct Encoder<'a> {
    data: &'a mut [u8],
    offset: usize,
    encoder: EndianEncoder,
}

impl fmt::Debug for Encoder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Change debug printing to print length instead of raw data.
        f.debug_struct("Encoder")
            .field("length", &self.data.len())
            .field("offset", &self.offset)
            .field("endian", &self.encoder.endian)
            .finish()
    }
}

impl Encoder<'_> {
    /** Initializes an [`Encoder`] based on the supplied [`Endian`] value.
     */
    pub fn to_bytes(data: &mut [u8], endian: Endian) -> Encoder {
        Encoder {
            data: data,
            offset: 0,
            encoder: match endian {
                Endian::Big => BIG_ENDIAN_ENCODER,
                Endian::Little => LITTLE_ENDIAN_ENCODER,
            },
        }
    }

    /** Checks if there is enough space in data slice to encode.
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    fn check_need(&self, count: usize) -> Result<(), EncodeError> {
        if self.available() >= count {
            Ok(())
        } else {
            Err(EncodeError::EndOfOutput {
                offset: self.offset,
                length: self.data.len(),
                count: count,
            })
        }
    }

    /** Returns the number of bytes still available for encoding in data slice.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Encoder, Endian};
     *
     * let data = &mut [0; 32];
     * let mut encoder = Encoder::to_bytes(data, Endian::Big);
     * assert_eq!(encoder.available(), 32);
     *
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.available(), 24);
     *
     * encoder.put_u64(0xfedcba9876543210).unwrap();
     * assert_eq!(encoder.available(), 16);
     * ```
     */
    pub fn available(&self) -> usize {
        // Gracefully handle offset errors, and just return 0.
        match self.data.len().checked_sub(self.offset) {
            Some(v) => v,
            None => 0,
        }
    }

    /** Returns the destination data capacity.
     *
     * Remains unchanged while encoding values.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Encoder, Endian};
     *
     * let data = &mut [0; 32];
     * let data_length = data.len();
     * let mut encoder = Encoder::to_bytes(data, Endian::Big);
     * assert_eq!(encoder.capacity(), data_length);
     *
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.capacity(), data_length);
     *
     * encoder.put_u64(0xfedcba9876543210).unwrap();
     * assert_eq!(encoder.capacity(), data_length);
     * ```
     */
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /** Returns the [`Endian`] of the encoder.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Encoder, Endian};
     *
     * // Some bytes.
     * let data = &mut [0; 32];
     *
     * // Create encoder.
     * let mut encoder = Encoder::to_bytes(data, Endian::Big);
     * assert!(matches!(encoder.endian(), Endian::Big));
     * ```
     */
    pub fn endian(&self) -> Endian {
        self.encoder.endian
    }

    /** Returns true if there is no more space for values to be encoded.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Encoder, Endian};
     *
     * // Some bytes.
     * let data = &mut [0; 32];
     *
     * // Create decoder.
     * let mut encoder = Encoder::to_bytes(data, Endian::Big);
     *
     * // Encode values.
     * let mut x = 0;
     * while !encoder.is_full() {
     *     encoder.put_u32(x);
     *     x += 1;
     * }
     * ```
     */
    pub fn is_full(&self) -> bool {
        self.offset >= self.data.len()
    }

    /** Returns the length of the encoded values.
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::endian::{Encoder, Endian};
     *
     * let data = &mut [0; 32];
     * let mut encoder = Encoder::to_bytes(data, Endian::Big);
     * assert_eq!(encoder.len(), 0);
     *
     * encoder.put_u64(0x0123456789abcdef).unwrap();
     * assert_eq!(encoder.len(), 8);
     *
     * encoder.put_u64(0xfedcba9876543210).unwrap();
     * assert_eq!(encoder.len(), 16);
     * ```
     */
    pub fn len(&self) -> usize {
        self.offset
    }

    /** Encodes 2 bytes.
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    fn put_2_bytes(&mut self, data: [u8; 2]) -> Result<(), EncodeError> {
        self.check_need(2)?;

        let start = self.offset;
        let end = start + 2;

        self.offset = end;

        self.data[start..end].copy_from_slice(&data);

        Ok(())
    }

    /** Encodes 4 bytes.
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    fn put_4_bytes(&mut self, data: [u8; 4]) -> Result<(), EncodeError> {
        self.check_need(4)?;

        let start = self.offset;
        let end = start + 4;

        self.offset = end;

        self.data[start..end].copy_from_slice(&data);

        Ok(())
    }

    /** Encodes 8 bytes.
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    fn put_8_bytes(&mut self, data: [u8; 8]) -> Result<(), EncodeError> {
        self.check_need(8)?;

        let start = self.offset;
        let end = start + 8;

        self.offset = end;

        self.data[start..end].copy_from_slice(&data);

        Ok(())
    }

    /** Encodes bytes.
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    pub fn put_bytes(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        let length = data.len();
        self.check_need(length)?;

        let start = self.offset;
        let end = start + length;

        self.offset = end;

        self.data[start..end].copy_from_slice(data);

        Ok(())
    }

    /** Encodes a [`u8`].
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    pub fn put_u8(&mut self, value: u8) -> Result<(), EncodeError> {
        self.check_need(1)?;
        self.data[self.offset] = value;
        self.offset += 1;

        Ok(())
    }

    /** Encodes a [`u16`].
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    pub fn put_u16(&mut self, value: u16) -> Result<(), EncodeError> {
        self.put_2_bytes((self.encoder.put_u16)(value))
    }

    /** Encodes a [`u32`].
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    pub fn put_u32(&mut self, value: u32) -> Result<(), EncodeError> {
        self.put_4_bytes((self.encoder.put_u32)(value))
    }

    /** Encodes a [`u64`].
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    pub fn put_u64(&mut self, value: u64) -> Result<(), EncodeError> {
        self.put_8_bytes((self.encoder.put_u64)(value))
    }

    /** Puts zero bytes as padding.
     *
     * # Errors
     *
     * Returns [`EncodeError`] if there are not enough bytes available.
     */
    pub fn put_zero_padding(&mut self, length: usize) -> Result<(), EncodeError> {
        self.check_need(length)?;

        let start = self.offset;
        let end = start + length;

        self.offset = end;

        self.data[start..end].fill(0);

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DecodeError {
    /** End of input data.
     *
     * - `offset` - Byte offset of data.
     * - `length` - Total length of data.
     * - `count`  - Number of bytes needed.
     */
    EndOfInput {
        offset: usize,
        length: usize,
        count: usize,
    },

    /** Magic mismatch.
     *
     * - `expected` - Expected magic value.
     * - `actual`   - Actual bytes.
     */
    InvalidMagic { expected: u64, actual: [u8; 8] },

    /** Non-zero padding.
     */
    NonZeroPadding {},

    /** Rewind past start.
     *
     * - `offset` - Byte offset of data.
     * - `count`  - Number of bytes needed to rewind.
     */
    RewindPastStart { offset: usize, count: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::EndOfInput {
                offset,
                length,
                count,
            } => {
                write!(
                    f,
                    "Endian end of input at offset {offset}, need {count} bytes, total length {length}"
                )
            }
            DecodeError::InvalidMagic { expected, actual } => write!(
                f,
                "Endian invalid magic expected {expected} actual {:?}",
                actual
            ),
            DecodeError::NonZeroPadding {} => write!(f, "Endian non-zero padding"),
            DecodeError::RewindPastStart { offset, count } => {
                write!(f, "Endian rewind at offset {offset}, need {count} bytes")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum EncodeError {
    /** End of output data.
     *
     * - `offset` - Byte offset of data.
     * - `length` - Total length of data.
     * - `count`  - Number of bytes needed.
     */
    EndOfOutput {
        offset: usize,
        length: usize,
        count: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::EndOfOutput {
                offset,
                length,
                count,
            } => {
                write!(
                    f,
                    "Endian end of output at offset {offset}, need {count} bytes, total length {length}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}
