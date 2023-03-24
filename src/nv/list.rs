/*

extern crate num;
extern crate strum;

use super::data_type::DataType;
use super::data_value::DataValue;

use std::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct Error {
    msg: &'static str,
    // source: NVError,
}

pub struct XDRDecoder<'a> {
    data: &'a [u8],
    index: usize,
}



impl XDRDecoder<'_> {
    fn get_u32(&mut self) -> Result<u32, Error> {
        if self.index > self.data.len() || self.data.len() - self.index < 4 {
            return Err(Error{msg:"xdr too short"})
        }

        let bytes_result: Result<[u8; 4], _> = self.data[self.index .. self.index + 4].try_into();
        match bytes_result {
            Ok(bytes) => {
                self.index += 4;
                Ok(u32::from_be_bytes(bytes))
            },
            Err(e) => Err(Error{msg:"xdr too short"})
        }

        // let bytes = &self.data[self.index .. self.index + 4];
        // let bytes: [u8; 4] = self.data[self.index .. self.index + 4].try_into();

        // match bytes {
        //     Ok(b) => Ok(u32::from_be_bytes(*b)),
        //     Err(e) => Err(Error{msg:"xdr too short"})
        // }

        // Ok(res)
    }
}
*/
/*

#[derive(Debug, FromPrimitive, strum::Display, PartialEq)]
pub enum Encoding {
    Native = 0,
    Xdr,
}

#[derive(Debug, FromPrimitive, strum::Display, PartialEq)]
pub enum Endian {
    Big = 0,
    Little,
}

#[derive(Debug)]
pub struct List {
    // encoding: Encoding,
    // endian: Endian,
}

// type Result<T> = std::result::Result<T, DoubleError>;
// #[derive(Debug, Clone)]
// pub enum ErrorCode {
//     Truncated,
// }

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NvList Error: {}", self.msg)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid first item to double")
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone)]
pub struct NVError {
}

impl error::Error for NVError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}


impl fmt::Display for NVError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid first item to double")
    }
}

pub fn decode(buf: &[u8]) -> Result<(), Error> {
    // Check that NvList header is not truncated.
    if buf.len() < 12 {
        return Err(Error{msg: "NvList header is truncated"});
    }

    ////////////////////////
    // Decode header.
    let (header_bytes, mut rest) = buf.split_at(12);

    // Get encoding.
    let encoding: Encoding = match num::FromPrimitive::from_u8(header_bytes[0]) {
        None => return Err(Error{msg: "NvList header unsupported encoding"}),
        Some(v) => v,
    };

    // Get endianness.
    let endian: Endian = match num::FromPrimitive::from_u8(header_bytes[0]) {
        None => return Err(Error{msg: "NvList header unsupported endian"}),
        Some(v) => v,
    };

    // Check for reserved bytes.
    if header_bytes[2] != 0 || header_bytes[3] != 0 {
        return Err(Error{msg: "NvList header reserved bytes are not 0"});
    }

    if encoding != Encoding::Xdr {
        return Err(Error{msg: "NvList unsupported encoding"})
    }
    if endian != Endian::Little {
        return Err(Error{msg: "NvList unsupported encoding"})
    }

    // In case of Encoding::Xdr, its always big endian.
    let version = i32::from_be_bytes(header_bytes[4 .. 8].try_into().unwrap());
    let flags = u32::from_be_bytes(header_bytes[8 .. 12].try_into().unwrap());

    ////////////////////////
    // Decode values.
    while rest.len() > 0 {
        // TODO(cybojanek): Is there a cleaner way to avoid scope escape?
        let mut nv_bytes: &[u8];

        ////////////////////////////////
        // Decode sizes.
        if rest.len() < 8 {
            return Err(Error{msg: "NvList pair header is truncated"});
        }
        (nv_bytes, rest) = rest.split_at(8);

        let encoded_size = u32::from_be_bytes(nv_bytes[0 .. 4].try_into().unwrap()) as usize;
        let decoded_size = u32::from_be_bytes(nv_bytes[4 .. 8].try_into().unwrap());

        // Check for end of list.
        if encoded_size == 0 && decoded_size == 0 {
            break;
        }

        // Check rest is large enough.
        // Encoded size includes sizes.
        if encoded_size < 8 || rest.len() < encoded_size - 8 {
            return Err(Error{msg: "NvList pair is truncated"});
        }

        // Get the rest of the nv bytes (subtract 8 because we already decoded sizes).
        (nv_bytes, rest) = rest.split_at(encoded_size - 8);

        // Get name size.
        if nv_bytes.len() < 4 {
            return Err(Error{msg: "NvList name size is truncated"});
        }
        let (name_size_bytes, nv_bytes) = nv_bytes.split_at(4);
        let name_size = u32::from_be_bytes(name_size_bytes.try_into().unwrap()) as usize;

        // Get name.
        if nv_bytes.len() < name_size {
            return Err(Error{msg: "NvList name is truncated"});
        }
        let (name_bytes, nv_bytes) = nv_bytes.split_at(name_size);

        let name = match std::str::from_utf8(name_bytes) {
            Ok(result) => result,
            Err(_) => return Err(Error{msg: "NvList name is not utf-8"}),
        };

        // Skip padding.
        let padding_size = if (name_bytes.len() % 4) == 0 { 0 } else { 4 - (name_bytes.len() % 4) };
        if nv_bytes.len() < padding_size {
            return Err(Error{msg: "NvList name padding is truncated"});
        }
        let (_, nv_bytes) = nv_bytes.split_at(padding_size);

        // Decode type.
        if nv_bytes.len() < 4 {
            return Err(Error{msg: "NvList type is truncated"});
        }
        let (type_bytes, nv_bytes) = nv_bytes.split_at(4);
        let type_number = i32::from_be_bytes(type_bytes.try_into().unwrap());

        let data_type: DataType = match num::FromPrimitive::from_i32(type_number) {
            None => return Err(Error{msg: "NvList data type is unkown"}),
            Some(v) => v,
        };

        // Decode number of elements.
        if nv_bytes.len() < 4 {
            return Err(Error{msg: "NvList element count is truncated"});
        }
        let (element_count_bytes, nv_bytes) = nv_bytes.split_at(4);
        let element_count = u32::from_be_bytes(element_count_bytes.try_into().unwrap());

        // println!("Name: {name}\t{data_type}\t{element_count}\t{}", nv_bytes.len());

        let value = match data_type {
            DataType::Uint64 => DataValue::Uint64(u64::from_be_bytes(nv_bytes[0 .. 8].try_into().unwrap())),
            // DataType::String => DataValue::String(
            // _ => return Err(Error{msg: "NvList data type is unsupported"}),
            _ => continue,
        };

        // let mut decoder = XDRDecoder{
        //     data: nv_bytes,
        //     index: 0,
        // };

        println!("Value: {:?}", value);
    }

    println!("A:{encoding} B:{endian}");
    println!("Version: {version}");
    println!("Flags: {flags}");

    Ok(())
}

*/


/*
#[cfg(test)]
mod tests {
    // use crate::nv::DataType;
    // use crate::nv::DataValue;
    use crate::nv::list::decode;

    use std::fs::File;
    use std::os::unix::prelude::FileExt;
    use  std::error::Error;

    #[test]
    fn test_decode() -> Result<(), Box<dyn Error>> {
        let path = "disk.img".to_string();
        let file = File::open(&path)?;
        let mut data = [0; 112 * 1024];
        file.read_at(&mut data, 16 * 1024)?;

        decode(&data)?;

        return Ok(());
    }
}
*/
