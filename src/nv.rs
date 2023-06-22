/*! Name Value decoder and encoder.
 *
 * A Name Value list is a sequence of Name Value [`Pair`].
 *
 * Header
 * ======
 * The first four bytes of the parent list are:
 * - [`Encoding`]
 * - [`Endian`]
 * - Two zero bytes
 *
 * [`Encoding`] and [`Endian`] specify how the rest of the data is encoded.
 * Nested lists inherit [`Encoding`] and [`Endian`] from the parent list.
 *
 * List
 * ====
 * A list starts with:
 * - [`u32`] version
 * - [`u32`] flags
 *
 * And is followed by a sequence of [`Pair`].
 *
 * Pair
 * ====
 * A [`Pair`] starts with:
 * - [`u32`] encoded size (of entire pair, including this number)
 * - [`u32`] decoded size (in memory TODO: how is this computed?)
 *
 * If both values are zero, then this is the end of the list.
 *
 * If they are not zero, then what follows is:
 * - [`String`] name
 * - [`u32`] [`DataType`]
 * - [`u32`] count for number of values in this pair
 *   - 0 for [`DataType::Boolean`].
 *   - 1 for all non array types [`DataType::Uint32`] etc...
 *   - 0 to N for array types [`DataType::Uint32Array`] etc...
 * - [`DataValue`] whose encoding corresponds to [`DataType`] and count
 *
 * Booleans
 * ========
 * A note about the two different boolean data types:
 * - [`DataType::Boolean`] has a count of 0, has no value, and is used as a flag.
 *   For example, the `features_for_read` list contains a sequence of flags,
 *   such as `org.openzfs:blake3`
 * - [`DataType::BooleanValue`] has a count of 1, and an actual value that can
 *   be [`true`] or [`false`]
 */
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::result::Result;
use core::result::Result::{Err, Ok};

#[cfg(feature = "std")]
use std::error;

extern crate strum;
use enum_as_inner::EnumAsInner;

use crate::endian::Endian;
use crate::xdr;

////////////////////////////////////////////////////////////////////////////////

/// Name Value Pair Data Type.
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum DataType {
    Boolean = 1,

    Byte,
    Int16,
    Uint16,
    Int32,
    Uint32,
    Int64,
    Uint64,
    String,

    ByteArray,
    Int16Array,
    Uint16Array,
    Int32Array,
    Uint32Array,
    Int64Array,
    Uint64Array,
    StringArray,

    HrTime,

    NvList,
    NvListArray,

    BooleanValue,

    Int8,
    Uint8,

    BooleanArray,
    Int8Array,
    Uint8Array,

    Double,
}

/** Checks the [`DataType`] and count are valid.
 *
 * # Errors
 *
 * Returns [`DecodeError::InvalidCount`] if count is invalid.
 */
fn check_data_type_count(data_type: DataType, count: usize) -> Result<(), DecodeError> {
    match data_type {
        // Boolean has no value.
        DataType::Boolean => match count {
            0 => Ok(()),
            _ => Err(DecodeError::InvalidCount {
                data_type: data_type,
                count: count,
            }),
        },
        // Non arrays have only one.
        DataType::Byte
        | DataType::Int16
        | DataType::Uint16
        | DataType::Int32
        | DataType::Uint32
        | DataType::Int64
        | DataType::Uint64
        | DataType::String
        | DataType::HrTime
        | DataType::NvList
        | DataType::BooleanValue
        | DataType::Int8
        | DataType::Uint8
        | DataType::Double => match count {
            1 => Ok(()),
            _ => Err(DecodeError::InvalidCount {
                data_type: data_type,
                count: count,
            }),
        },
        // Arrays have from 0 to N values.
        DataType::ByteArray
        | DataType::Int16Array
        | DataType::Uint16Array
        | DataType::Int32Array
        | DataType::Uint32Array
        | DataType::Int64Array
        | DataType::Uint64Array
        | DataType::StringArray
        | DataType::NvListArray
        | DataType::BooleanArray
        | DataType::Int8Array
        | DataType::Uint8Array => Ok(()),
    }
}

/// Name Value Pair Data Value.
#[derive(Debug)]
pub enum DataValue<'a> {
    Boolean(),

    Byte(u8),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    String(&'a str),

    ByteArray(&'a [u8]),
    Int16Array(&'a [i16]),
    Uint16Array(&'a [u16]),
    Int32Array(&'a [i32]),
    Uint32Array(&'a [u32]),
    Int64Array(&'a [i64]),
    Uint64Array(&'a [u64]),
    StringArray(&'a [&'a str]),

    HrTime(i64),

    NvList(List<'a>),
    NvListArray(&'a [List<'a>]),

    BooleanValue(bool),

    Int8(i8),
    Uint8(u8),

    BooleanArray(&'a [bool]),
    Int8Array(&'a [i8]),
    Uint8Array(&'a [u8]),

    Double(f64),
}

/// Name Value Pair.
#[derive(Debug)]
pub struct Pair<'a> {
    pub name: &'a str,
    pub value: DataValue<'a>,
}

/// Name Value List.
#[derive(Debug)]
pub struct List<'a> {
    pub encoding: Encoding,
    pub endian: Endian,
    pub pairs: &'a [Pair<'a>],
    pub unique: Unique,
}

////////////////////////////////////////////////////////////////////////////////

// Decoded Name Value Pair Data Value.
#[derive(Debug, EnumAsInner)]
pub enum DecodedDataValue<'a> {
    Boolean(),

    Byte(u8),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    String(&'a str),

    ByteArray(&'a [u8]),
    Int16Array(ArrayDecoder<'a, i16>),
    Uint16Array(ArrayDecoder<'a, u16>),
    Int32Array(ArrayDecoder<'a, i32>),
    Uint32Array(ArrayDecoder<'a, u32>),
    Int64Array(ArrayDecoder<'a, i64>),
    Uint64Array(ArrayDecoder<'a, u64>),
    StringArray(ArrayDecoder<'a, &'a str>),

    HrTime(i64),

    NvList(Decoder<'a>),
    NvListArray(ArrayDecoder<'a, Decoder<'a>>),

    BooleanValue(bool),

    Int8(i8),
    Uint8(u8),

    BooleanArray(ArrayDecoder<'a, bool>),
    Int8Array(ArrayDecoder<'a, i8>),
    Uint8Array(ArrayDecoder<'a, u8>),

    Double(f64),
}

/** An name value pair list decoder.
 */
#[derive(Debug)]
pub struct Decoder<'a> {
    decoder: xdr::Decoder<'a>,
    encoding: Encoding,
    endian: Endian,
    pub unique: Unique,
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct ArrayDecoder<'a, T> {
    decoder: xdr::Decoder<'a>,
    count: usize,
    index: Cell<usize>,
    encoding: Encoding,
    endian: Endian,
    phantom: PhantomData<T>,
}

impl<T> ArrayDecoder<'_, T> {
    /// Returns the number of elements in the entire array.
    pub fn capacity(&self) -> usize {
        self.count
    }

    /// Returns number of elements still to be decoded.
    pub fn len(&self) -> usize {
        match self.count.checked_sub(self.index.get()) {
            Some(v) => v,
            None => 0,
        }
    }

    /// Resets the decoder to the start of the data.
    pub fn reset(&self) {
        self.decoder.reset();
        self.index.set(0);
    }
}

impl<'a> ArrayDecoder<'a, &str> {
    /** Returns the next element.
     *
     * - Call while [`ArrayDecoder::len`] is greater than 0.
     *
     * # Errors.
     *
     * Returns [`DecodeError`] on error.
     */
    pub fn get(&self) -> Result<&str, DecodeError> {
        let index = self.index.get();

        if index < self.count {
            self.index.set(index + 1);
            Ok(self.decoder.get_str()?)
        } else {
            Err(DecodeError::EndOfArray {})
        }
    }
}

impl<T: xdr::GetFromDecoder> ArrayDecoder<'_, T> {
    /** Returns the next element.
     *
     * - Call while [`ArrayDecoder::len`] is greater than 0.
     *
     * # Errors.
     *
     * Returns [`DecodeError`] on error.
     */
    pub fn get(&self) -> Result<T, DecodeError> {
        let index = self.index.get();

        if index < self.count {
            self.index.set(index + 1);
            Ok(self.decoder.get()?)
        } else {
            Err(DecodeError::EndOfArray {})
        }
    }
}

impl<'a> ArrayDecoder<'a, Decoder<'a>> {
    /** Returns the next element.
     *
     * - Call while [`ArrayDecoder::len`] is greater than 0.
     *
     * # Errors.
     *
     * Returns [`DecodeError`] on error.
     */
    pub fn get(&'a self) -> Result<Decoder<'a>, DecodeError> {
        let index = self.index.get();

        if index < self.count {
            self.index.set(index + 1);

            // Get the rest of the bytes.
            let starting_length = self.decoder.len();
            let data = self.decoder.get_n_bytes(starting_length)?;

            // Create a temporary decoder.
            let decoder = Decoder::from_partial(self.encoding, self.endian, data)?;

            // Decode until end of list or error.
            loop {
                match decoder.next_pair() {
                    Ok(v) => match v {
                        Some(_) => continue,
                        None => break,
                    },
                    Err(v) => return Err(v),
                }
            }

            // Compute number of bytes used for this list.
            let bytes_used = starting_length - self.decoder.len();

            // Rewind decoder back.
            self.decoder.rewind(starting_length)?;

            // Get bytes actually used.
            let data = self.decoder.get_n_bytes(bytes_used)?;

            // Return decoder.
            Decoder::from_partial(self.encoding, self.endian, data)
        } else {
            Err(DecodeError::EndOfArray {})
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct DecodedPair<'a> {
    pub name: &'a str,
    pub value: DecodedDataValue<'a>,
}

impl<'a> DecodedPair<'_> {
    /// Gets the data type of the decoded pair.
    pub fn data_type(&self) -> DataType {
        match self.value {
            DecodedDataValue::Boolean() => DataType::Boolean,

            DecodedDataValue::Byte(_) => DataType::Byte,
            DecodedDataValue::Int16(_) => DataType::Int16,
            DecodedDataValue::Uint16(_) => DataType::Uint16,
            DecodedDataValue::Int32(_) => DataType::Int32,
            DecodedDataValue::Uint32(_) => DataType::Uint32,
            DecodedDataValue::Int64(_) => DataType::Int64,
            DecodedDataValue::Uint64(_) => DataType::Uint64,
            DecodedDataValue::String(_) => DataType::String,

            DecodedDataValue::ByteArray(_) => DataType::ByteArray,
            DecodedDataValue::Int16Array(_) => DataType::Int16Array,
            DecodedDataValue::Uint16Array(_) => DataType::Uint16Array,
            DecodedDataValue::Int32Array(_) => DataType::Int32Array,
            DecodedDataValue::Uint32Array(_) => DataType::Uint32Array,
            DecodedDataValue::Int64Array(_) => DataType::Int64Array,
            DecodedDataValue::Uint64Array(_) => DataType::Uint64Array,
            DecodedDataValue::StringArray(_) => DataType::StringArray,

            DecodedDataValue::HrTime(_) => DataType::HrTime,

            DecodedDataValue::NvList(_) => DataType::NvList,
            DecodedDataValue::NvListArray(_) => DataType::NvListArray,

            DecodedDataValue::BooleanValue(_) => DataType::BooleanValue,

            DecodedDataValue::Int8(_) => DataType::Int8,
            DecodedDataValue::Uint8(_) => DataType::Uint8,

            DecodedDataValue::BooleanArray(_) => DataType::BooleanArray,
            DecodedDataValue::Int8Array(_) => DataType::Int8Array,
            DecodedDataValue::Uint8Array(_) => DataType::Uint8Array,

            DecodedDataValue::Double(_) => DataType::Double,
        }
    }
}

impl Decoder<'_> {
    /** Instantiates a NV list [`Decoder`] from a slice of bytes.
     *
     * # Errors.
     *
     * Returns [`DecodeError`] on error.
     */
    pub fn from_bytes(data: &[u8]) -> Result<Decoder, DecodeError> {
        // Check that NvList header is not truncated.
        if data.len() < 4 {
            return Err(DecodeError::EndOfInput {
                offset: 0,
                length: data.len(),
                count: 4,
                detail: "NV List header is truncated",
            });
        }

        // Get the first four bytes.
        let (header, rest) = data.split_at(4);

        let encoding = header[0];
        let endian = header[1];
        let reserved_0 = header[2];
        let reserved_1 = header[3];

        // Decode encoding.
        let encoding: Encoding = match num::FromPrimitive::from_u8(encoding) {
            None => return Err(DecodeError::InvalidEncoding { encoding: encoding }),
            Some(v) => v,
        };

        // Decode endian.
        let endian = match header[1] {
            0 => Endian::Big,
            1 => Endian::Little,
            _ => return Err(DecodeError::InvalidEndian { endian: endian }),
        };

        // Check reserved bytes.
        if reserved_0 != 0 || reserved_1 != 0 {
            return Err(DecodeError::InvalidReservedBytes {
                reserved: [reserved_0, reserved_1],
            });
        }

        Decoder::from_partial(encoding, endian, rest)
    }

    /** Instantiates a nested NV list [`Decoder`] from a slice of bytes.
     *
     * - Encoding, and endian must be the same as the parent list.
     *
     * # Errors.
     *
     * Returns [`DecodeError`] on error.
     */
    fn from_partial(
        encoding: Encoding,
        endian: Endian,
        data: &[u8],
    ) -> Result<Decoder, DecodeError> {
        // Check encoding.
        match encoding {
            Encoding::Native => todo!("Implement Native decoding"),
            Encoding::Xdr => (),
        }

        // NOTE: For XDR, it is always big endian, no matter what the endian
        //       field says.
        let decoder = xdr::Decoder::from_bytes(data);

        // NvList version.
        let version = decoder.get()?;
        if version != 0 {
            return Err(DecodeError::InvalidVersion { version: version });
        }

        // NvList flags.
        let flags: u32 = decoder.get()?;
        let unique_flags = flags & 0x3;

        // Check for unknown flags.
        if unique_flags != flags {
            return Err(DecodeError::InvalidFlags { flags: flags });
        }

        // Decode unique flags.
        let unique: Unique = match num::FromPrimitive::from_u32(unique_flags) {
            None => return Err(DecodeError::InvalidFlags { flags: flags }),
            Some(v) => v,
        };

        Ok(Decoder {
            decoder: decoder,
            encoding: encoding,
            endian: endian,
            unique: unique,
        })
    }

    /** Gets the next [`DecodedPair`].
     *
     * - Returns [`None`] at end of list.
     *
     * # Errors.
     *
     * Returns [`DecodeError`] on error.
     */
    pub fn next_pair(&self) -> Result<Option<DecodedPair>, DecodeError> {
        // Keep track of starting length, to verify encoded_size, and
        // construct nested NV List structures.
        let starting_length = self.decoder.len();

        // Encoded and decoded sizes.
        let encoded_size = self.decoder.get_usize()?;
        let decoded_size = self.decoder.get_usize()?;

        // Check for end of list.
        if encoded_size == 0 && decoded_size == 0 {
            return Ok(None);
        }

        // Name.
        let name = self.decoder.get_str()?;

        // Data type.
        let data_type = self.decoder.get_u32()?;
        let data_type = match num::FromPrimitive::from_u32(data_type) {
            Some(v) => v,
            None => {
                return Err(DecodeError::InvalidDataType {
                    data_type: data_type,
                })
            }
        };

        // Number of elements.
        let element_count = self.decoder.get_usize()?;

        // Number of bytes remaining.
        let bytes_used = starting_length - self.decoder.len();
        let bytes_rem = match encoded_size.checked_sub(bytes_used) {
            Some(v) => v,
            None => {
                // Consumed too many bytes.
                return Err(DecodeError::InvalidEncodedSize {
                    encoded_size: encoded_size,
                    used: bytes_used,
                });
            }
        };

        // Check count.
        check_data_type_count(data_type, element_count)?;

        // Decode data value.
        let value = match data_type {
            DataType::Boolean => DecodedDataValue::Boolean(),

            DataType::Byte => DecodedDataValue::Byte(self.decoder.get()?),
            DataType::Int16 => DecodedDataValue::Int16(self.decoder.get()?),
            DataType::Uint16 => DecodedDataValue::Uint16(self.decoder.get()?),
            DataType::Int32 => DecodedDataValue::Int32(self.decoder.get()?),
            DataType::Uint32 => DecodedDataValue::Uint32(self.decoder.get()?),
            DataType::Int64 => DecodedDataValue::Int64(self.decoder.get()?),
            DataType::Uint64 => DecodedDataValue::Uint64(self.decoder.get()?),
            DataType::String => DecodedDataValue::String(self.decoder.get_str()?),

            DataType::ByteArray => DecodedDataValue::ByteArray(self.decoder.get_bytes()?),
            DataType::Int16Array => DecodedDataValue::Int16Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Uint16Array => DecodedDataValue::Uint16Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Int32Array => DecodedDataValue::Int32Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Uint32Array => DecodedDataValue::Uint32Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Int64Array => DecodedDataValue::Int64Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 8)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Uint64Array => DecodedDataValue::Uint64Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 8)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::StringArray => DecodedDataValue::StringArray(ArrayDecoder {
                // TODO(cybojanek): Verify length of strings at this point?
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(bytes_rem)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),

            DataType::HrTime => DecodedDataValue::HrTime(self.decoder.get()?),

            DataType::NvList => DecodedDataValue::NvList(Decoder::from_partial(
                self.encoding,
                self.endian,
                // TODO(cybojanek): Verify length of list at this point?
                self.decoder.get_n_bytes(bytes_rem)?,
            )?),
            DataType::NvListArray => DecodedDataValue::NvListArray(ArrayDecoder {
                // TODO(cybojanek): Verify length of list at this point?
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(bytes_rem)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),

            DataType::BooleanValue => DecodedDataValue::BooleanValue(self.decoder.get()?),

            DataType::Int8 => DecodedDataValue::Int8(self.decoder.get()?),
            DataType::Uint8 => DecodedDataValue::Uint8(self.decoder.get()?),

            DataType::BooleanArray => DecodedDataValue::BooleanArray(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Int8Array => DecodedDataValue::Int8Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),
            DataType::Uint8Array => DecodedDataValue::Uint8Array(ArrayDecoder {
                decoder: xdr::Decoder::from_bytes(self.decoder.get_n_bytes(element_count * 4)?),
                count: element_count,
                index: Cell::new(0),
                endian: self.endian,
                encoding: self.encoding,
                phantom: PhantomData,
            }),

            DataType::Double => DecodedDataValue::Double(self.decoder.get()?),
        };

        // Number of bytes remaining.
        let bytes_used = starting_length - self.decoder.len();
        let bytes_rem = match encoded_size.checked_sub(bytes_used) {
            Some(v) => v,
            None => {
                // Consumed too many bytes.
                return Err(DecodeError::InvalidEncodedSize {
                    encoded_size: encoded_size,
                    used: bytes_used,
                });
            }
        };

        // Some bytes left.
        if bytes_rem > 0 {
            return Err(DecodeError::InvalidEncodedSize {
                encoded_size: encoded_size,
                used: bytes_used,
            });
        }

        Ok(Some(DecodedPair {
            name: name,
            value: value,
        }))
    }

    /// Reset the decoder to the start of the data.
    pub fn reset(&self) {
        self.decoder.reset();

        // Skip version and flags.
        // NOTE(cybojanek): Ignore return.
        let _ = self.decoder.skip(8);
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Name Value List encoding.
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum Encoding {
    Native = 0,
    Xdr,
}

/// Name Value List Unique.
#[derive(Clone, Copy, Debug, FromPrimitive, strum::Display)]
pub enum Unique {
    None = 0,
    Name = 1,
    NameType = 2,
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum DecodeError {
    /** End of array.
     */
    EndOfArray {},

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
        detail: &'static str,
    },

    /** Data type has an invalid count.
     *
     * - `data_type` - Data type.
     * - `count`     - Count.
     */
    InvalidCount { data_type: DataType, count: usize },

    /** Invalid data_type.
     *
     * - `data_type` - DataType.
     */
    InvalidDataType { data_type: u32 },

    /** Invalid encoded size.
     *
     * - `encoded_size` - Encoded size.
     * - `used` - Bytes used.
     */
    InvalidEncodedSize { encoded_size: usize, used: usize },

    /** Invalid encoding.
     *
     * - `encoding` - Encoding.
     */
    InvalidEncoding { encoding: u8 },

    /** Invalid endian.
     *
     * - `endian` - Endian.
     */
    InvalidEndian { endian: u8 },

    /** Invalid flags.
     *
     * - `flags` - Flags.
     */
    InvalidFlags { flags: u32 },

    /** Invalid reserved bytes.
     *
     * - `reserved` - Reserved.
     */
    InvalidReservedBytes { reserved: [u8; 2] },

    /** Invalid version.
     *
     * - `version` - Version.
     */
    InvalidVersion { version: u32 },

    /** XDR decoding error.
     *
     * - `err` - Error.
     */
    Xdr { err: xdr::DecodeError },
}

impl From<xdr::DecodeError> for DecodeError {
    fn from(value: xdr::DecodeError) -> Self {
        DecodeError::Xdr { err: value }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::EndOfArray {} => {
                write!(f, "NV List array end")
            }
            DecodeError::EndOfInput {
                offset,
                length,
                count,
                detail,
            } => {
                write!(
                    f,
                    "NV List end of input at offset {offset}, need {count} bytes, total length {length}, detail: {detail}"
                )
            }
            DecodeError::InvalidDataType { data_type } => {
                write!(f, "NV List invalid data type {data_type}")
            }
            DecodeError::InvalidEncodedSize { encoded_size, used } => {
                write!(f, "NV List invalid encoded size {encoded_size} used {used}")
            }
            DecodeError::InvalidEncoding { encoding } => {
                write!(f, "NV List invalid encoding {encoding}")
            }
            DecodeError::InvalidEndian { endian } => {
                write!(f, "NV List invalid endian {endian}")
            }
            DecodeError::InvalidCount { data_type, count } => {
                write!(f, "NV Pair invalid count {count} for data type {data_type}")
            }
            DecodeError::InvalidFlags { flags } => {
                write!(f, "NV List invalid flags {flags}")
            }
            DecodeError::InvalidReservedBytes { reserved } => {
                let a = reserved[0];
                let b = reserved[1];
                write!(f, "NV List invalid reserved bytes 0x{a:02x} 0x{b:02x}")
            }
            DecodeError::InvalidVersion { version } => {
                write!(f, "NV List invalid version {version}")
            }
            DecodeError::Xdr { err } => {
                write!(f, "NV List XDR decoding error: {err}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DecodeError::Xdr { err } => Some(err),
            _ => None,
        }
    }
}
