/*! An XDR decoder and encoder.
 *
 * [XDR](https://www.rfc-editor.org/rfc/rfc4506) is a standard of encoding
 * numbers and strings to bytes.
 *
 * - Boolean values are encoded as the number 0 [`false`], 1 [`true`].
 * - Numbers are encoded in big endian format.
 * - Strings and byte arrays are encoded as a length followed by the bytes,
 *   padded to a multiple of four. The length does not include the padding.
 * - [`Decoder`] uses an internal [`Cell`] field for the `offset` field
 *   in order to implement a split borrow.
 */

use core::cell::Cell;
use core::fmt;
use core::marker::Sized;
use core::num;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

////////////////////////////////////////////////////////////////////////////////

/** An XDR decoder.
 */
#[derive(Debug)]
pub struct Decoder<'a> {
    data: &'a [u8],
    offset: Cell<usize>,
}

impl Decoder<'_> {
    /** Instantiate a [`Decoder`] from a slice of bytes.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(&data);
     * assert_eq!(decoder.len(), 8);
     *
     * // Decode values.
     * let a: bool = decoder.get().unwrap();
     * assert_eq!(decoder.len(), 4);
     *
     * let b: bool = decoder.get().unwrap();
     * assert_eq!(decoder.len(), 0);
     *
     * assert_eq!(decoder.is_empty(), true);
     *
     * assert_eq!(a, true);
     * assert_eq!(b, false);
     * ```
     */
    pub fn from_bytes(data: &[u8]) -> Decoder {
        Decoder {
            data: data,
            offset: Cell::new(0),
        }
    }

    /** Checks if there are enough bytes to consume from the data slice.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are enough bytes available, or internal
     * offset is malformed.
     */
    fn check_need(&self, count: usize) -> Result<(), DecodeError> {
        // Safely compute bytes remaining.
        let offset = self.offset.get();
        let length = self.data.len();
        let remaining = match length.checked_sub(offset) {
            Some(v) => v,
            None => {
                return Err(DecodeError::InvalidOffset {
                    offset: offset,
                    length: length,
                })
            }
        };

        // Check if there are enough remaining.
        if remaining >= count {
            Ok(())
        } else {
            Err(DecodeError::EndOfInput {
                offset: offset,
                length: length,
                count: count,
            })
        }
    }

    /** Consume padding to align offset to a multiple of 4.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are enough bytes available, or internal
     * offset is malformed.
     */
    fn consume_padding(&self) -> Result<(), DecodeError> {
        // Compute padding.
        let offset = self.offset.get();
        let remainder = offset % 4;
        let padding = if remainder == 0 { 0 } else { 4 - remainder };

        // Check bounds for padding.
        self.check_need(padding)?;

        // TODO(cybojanek): Validate that padding is all zeros?

        // Skip the padding.
        self.offset.set(offset + padding);

        Ok(())
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
     * use zfs::xdr::Decoder;
     *
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
     * ];
     * let decoder = Decoder::from_bytes(data);
     *
     * assert_eq!(decoder.capacity(), data.len());
     * decoder.get_u64();
     *
     * assert_eq!(decoder.capacity(), data.len());
     * decoder.get_u64();
     *
     * assert_eq!(decoder.capacity(), data.len());
     * ```
     */
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /** Returns true if there are no more bytes to decode.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * while !decoder.is_empty() {
     *     let a = decoder.get_bool().unwrap();
     *     assert_eq!(a, true);
     * }
     * ```
     */
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /** Returns length of bytes remaining to be processed.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * assert_eq!(decoder.len(), 8);
     * let a = decoder.get_bool().unwrap();
     * assert_eq!(decoder.len(), 4);
     * let b = decoder.get_bool().unwrap();
     * assert_eq!(decoder.len(), 0);
     *
     * assert_eq!(a, true);
     * assert_eq!(b, false);
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

    /** Skips length number of bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     */
    pub fn skip(&self, length: usize) -> Result<(), DecodeError> {
        self.check_need(length)?;
        self.offset.set(self.offset.get() + length);
        self.consume_padding()?;
        Ok(())
    }

    /** Returns 4 bytes.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     */
    fn get_4_bytes(&self) -> Result<[u8; 4], DecodeError> {
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
     * Returns [`DecodeError`] if there are not enough bytes available.
     */
    fn get_8_bytes(&self) -> Result<[u8; 8], DecodeError> {
        self.check_need(8)?;

        let start = self.offset.get();
        let end = start + 8;

        self.offset.set(end);

        Ok(<[u8; 8]>::try_from(&self.data[start..end]).unwrap())
    }

    /** Returns length number of bytes.
     *
     * Consumes padding bytes if length is not a multiple of 4.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x61, 0x62, 0x63, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_n_bytes(5).unwrap();
     * let d = [0x12, 0x34, 0x56, 0x78, 0x61];
     *
     * assert_eq!(a, d);
     * ```
     *
     * Truncated padding:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x61, 0x62, 0x63];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for padding.
     * assert!(decoder.get_n_bytes(5).is_err());
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x61, 0x62, 0x63];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for string.
     * assert!(decoder.get_n_bytes(8).is_err());
     * ```
     */
    pub fn get_n_bytes(&self, length: usize) -> Result<&[u8], DecodeError> {
        // Check bounds for length.
        self.check_need(length)?;

        // Start and end of bytes.
        let start = self.offset.get();
        let end = start + length;

        // Consume bytes.
        let value = &self.data[start..end];
        self.offset.set(end);

        // Consume padding.
        self.consume_padding()?;

        // Return bytes.
        Ok(value)
    }

    /** Decodes a [`bool`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are enough bytes available, or the value
     * is not 0 nor 1.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_bool().unwrap();
     * let b = decoder.get_bool().unwrap();
     *
     * assert_eq!(a, true);
     * assert_eq!(b, false);
     * ```
     *
     * Incorrect bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // 3 is not a valid boolean.
     * assert!(decoder.get_bool().is_err());
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_bool().is_err());
     * ```
     */
    pub fn get_bool(&self) -> Result<bool, DecodeError> {
        let offset = self.offset.get();
        let value = self.get_u32()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidBoolean {
                offset: offset,
                value: value,
            }),
        }
    }

    /** Decodes a [`&[u8]`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_bytes().unwrap();
     * let d = [0x61, 0x62, 0x63];
     *
     * assert_eq!(a, d);
     * ```
     *
     * Truncated padding:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for padding.
     * assert!(decoder.get_bytes().is_err());
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x05, 0x61, 0x62, 0x63, 0x64];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for string.
     * assert!(decoder.get_bytes().is_err());
     * ```
     */
    pub fn get_bytes(&self) -> Result<&[u8], DecodeError> {
        let length = self.get_usize()?;
        self.get_n_bytes(length)
    }

    /** Decodes an [`f32`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     */
    pub fn get_f32(&self) -> Result<f32, DecodeError> {
        let bytes = self.get_4_bytes()?;
        Ok(f32::from_be_bytes(bytes))
    }

    /** Decodes an [`f64`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     */
    pub fn get_f64(&self) -> Result<f64, DecodeError> {
        let bytes = self.get_8_bytes()?;
        Ok(f64::from_be_bytes(bytes))
    }

    /** Decodes an [`i32`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0xed, 0xcb, 0xa9, 0x88];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_i32().unwrap();
     * let b = decoder.get_i32().unwrap();
     *
     * assert_eq!(a, 0x12345678);
     * assert_eq!(b, -0x12345678);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_i32().is_err());
     * ```
     */
    pub fn get_i32(&self) -> Result<i32, DecodeError> {
        let bytes = self.get_4_bytes()?;
        Ok(i32::from_be_bytes(bytes))
    }

    /** Decodes an [`i64`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
     *     0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x10,
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_i64().unwrap();
     * let b = decoder.get_i64().unwrap();
     *
     * assert_eq!(a, 0x123456789abcdef0);
     * assert_eq!(b, -0x123456789abcdef0);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_i64().is_err());
     * ```
     */
    pub fn get_i64(&self) -> Result<i64, DecodeError> {
        let bytes = self.get_8_bytes()?;
        Ok(i64::from_be_bytes(bytes))
    }

    /** Decodes a [`u32`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_u32().unwrap();
     *
     * assert_eq!(a, 0xf2345678);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u32().is_err());
     * ```
     */
    pub fn get_u32(&self) -> Result<u32, DecodeError> {
        let bytes = self.get_4_bytes()?;
        Ok(u32::from_be_bytes(bytes))
    }

    /** Decodes a [`u64`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * # Examples
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_u64().unwrap();
     *
     * assert_eq!(a, 0xf23456789abcdef0);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_u64().is_err());
     * ```
     */
    pub fn get_u64(&self) -> Result<u64, DecodeError> {
        let bytes = self.get_8_bytes()?;
        Ok(u64::from_be_bytes(bytes))
    }

    /** Decodes a [`usize`] for array or string lengths.
     *
     * XDR uses unsigned 32 bit values for array and string lengths.
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available.
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56, 0x78];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_usize().unwrap();
     *
     * assert_eq!(a, 0xf2345678);
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0xf2, 0x34, 0x56];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 4 bytes.
     * assert!(decoder.get_usize().is_err());
     * ```
     */
    pub fn get_usize(&self) -> Result<usize, DecodeError> {
        let offset = self.offset.get();
        let value = self.get_u32()?;

        match usize::try_from(value) {
            Ok(v) => Ok(v),
            Err(e) => Err(DecodeError::SizeConversion {
                offset: offset,
                value: value,
                err: e,
            }),
        }
    }

    /** Decodes a [`str`].
     *
     * # Errors
     *
     * Returns [`DecodeError`] if there are not enough bytes available, or the
     * bytes are not a valid UTF8 string.
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63, 0x00,
     *     0x00, 0x00, 0x00, 0x02, 0x64, 0x65, 0x00, 0x00,
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a = decoder.get_str().unwrap();
     * let b = decoder.get_str().unwrap();
     *
     * assert_eq!(a, "abc");
     * assert_eq!(b, "de");
     * ```
     *
     * Truncated padding:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for padding.
     * assert!(decoder.get_str().is_err());
     * ```
     *
     * Truncated bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x05, 0x61, 0x62, 0x63, 0x64];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for string.
     * assert!(decoder.get_str().is_err());
     * ```
     *
     * Malformed utf8 bytes:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0xff, 0x00];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Need 1 more byte for string.
     * assert!(decoder.get_str().is_err());
     * ```
     */
    pub fn get_str(&self) -> Result<&str, DecodeError> {
        let length = self.get_usize()?;
        let offset = self.offset.get();
        let data = self.get_n_bytes(length)?;

        match core::str::from_utf8(data) {
            Ok(v) => Ok(v),
            Err(e) => Err(DecodeError::InvalidStr {
                offset: offset,
                length: length,
                err: e,
            }),
        }
    }

    /** Decodes a value using the [`GetFromDecoder`] trait for F.
     *
     * # Errors
     *
     * Returns [`DecodeError`] in case of decoding errors.
     *
     * Basic usage:
     *
     * ```
     * use zfs::xdr::Decoder;
     *
     * // Some bytes.
     * let data = &[
     *     0x00, 0x00, 0x00, 0x01,                         // bool
     *     0xed, 0xcb, 0xa9, 0x88,                         // i32
     *     0xf2, 0x34, 0x56, 0x78,                         // u32
     *     0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x10, // i64
     *     0xf2, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // u64
     *     0xf2, 0x34, 0x56, 0x78,                         // usize
     * ];
     *
     * // Create decoder.
     * let decoder = Decoder::from_bytes(data);
     *
     * // Decode values.
     * let a: bool = decoder.get().unwrap();
     * let b: i32 = decoder.get().unwrap();
     * let c: u32 = decoder.get().unwrap();
     * let d: i64 = decoder.get().unwrap();
     * let e: u64 = decoder.get().unwrap();
     * let f: usize = decoder.get().unwrap();
     *
     * assert_eq!(a, true);
     * assert_eq!(b, -0x12345678);
     * assert_eq!(c, 0xf2345678);
     * assert_eq!(d, -0x123456789abcdef0);
     * assert_eq!(e, 0xf23456789abcdef0);
     * assert_eq!(f, 0xf2345678);
     *
     * assert!(decoder.is_empty());
     * ```
     */
    pub fn get<F: GetFromDecoder>(&self) -> Result<F, DecodeError> {
        GetFromDecoder::get_from_decoder(self)
    }
}

////////////////////////////////////////////////////////////////////////////////

/** [`GetFromDecoder`] is a trait that gets from the [`Decoder`] to the type.
 */
pub trait GetFromDecoder: Sized {
    fn get_from_decoder(decoder: &Decoder) -> Result<Self, DecodeError>;
}

impl GetFromDecoder for bool {
    fn get_from_decoder(decoder: &Decoder) -> Result<bool, DecodeError> {
        decoder.get_bool()
    }
}

impl GetFromDecoder for f32 {
    fn get_from_decoder(decoder: &Decoder) -> Result<f32, DecodeError> {
        decoder.get_f32()
    }
}

impl GetFromDecoder for f64 {
    fn get_from_decoder(decoder: &Decoder) -> Result<f64, DecodeError> {
        decoder.get_f64()
    }
}

impl GetFromDecoder for i32 {
    fn get_from_decoder(decoder: &Decoder) -> Result<i32, DecodeError> {
        decoder.get_i32()
    }
}

impl GetFromDecoder for i64 {
    fn get_from_decoder(decoder: &Decoder) -> Result<i64, DecodeError> {
        decoder.get_i64()
    }
}

impl GetFromDecoder for u32 {
    fn get_from_decoder(decoder: &Decoder) -> Result<u32, DecodeError> {
        decoder.get_u32()
    }
}

impl GetFromDecoder for u64 {
    fn get_from_decoder(decoder: &Decoder) -> Result<u64, DecodeError> {
        decoder.get_u64()
    }
}

impl GetFromDecoder for usize {
    fn get_from_decoder(decoder: &Decoder) -> Result<usize, DecodeError> {
        decoder.get_usize()
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

    /** Invalid boolean value.
     *
     * - `offset` - Byte offset of data.
     * - `value`  - Boolean numerical value.
     */
    InvalidBoolean { offset: usize, value: u32 },

    /** Invalid offset is past data.
     *
     * This should never occur.
     *
     * - `offset` - Byte offset of data.
     * - `length` - Total length of data.
     */
    InvalidOffset { offset: usize, length: usize },

    /** Invalid str.
     *
     * - `offset` - Byte offset of data.
     * - `length` - Length of str.
     * - `err`    - Decoding error.
     */
    InvalidStr {
        offset: usize,
        length: usize,
        err: core::str::Utf8Error,
    },

    /** Size conversion error from [`u32`] to [`usize`].
     *
     * - `offset` - Byte offset of data.
     * - `value`  - Value of failed conversion.
     */
    SizeConversion {
        offset: usize,
        value: u32,
        err: num::TryFromIntError,
    },
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
                    "XDR end of input at offset {offset}, need {count} bytes, total length {length}"
                )
            }
            DecodeError::InvalidBoolean { offset, value } => {
                write!(f, "XDR invalid boolean at offset {offset}, value {value}")
            }
            DecodeError::InvalidOffset { offset, length } => {
                write!(f, "XDR invalid offset {offset}, total length {length}")
            }
            DecodeError::InvalidStr {
                offset,
                length,
                err,
            } => {
                write!(
                    f,
                    "XDR invalid UTF8 str of length {length} at offset {offset} err {err}"
                )
            }
            DecodeError::SizeConversion { offset, value, err } => {
                write!(
                    f,
                    "XDR size conversion error at offset {offset}, value {value} err {err}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DecodeError::InvalidStr {
                offset: _,
                length: _,
                err,
            } => Some(err),
            DecodeError::SizeConversion {
                offset: _,
                value: _,
                err,
            } => Some(err),
            _ => None,
        }
    }
}
