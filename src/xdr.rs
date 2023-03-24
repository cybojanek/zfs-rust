// use std::error;
use std::fmt;

// https://doc.rust-lang.org/std/error/trait.Error.html
pub enum Error {
    EndOfInput(usize, usize),
    IndexOutOfBounds(usize, usize),
    InvalidBoolean(usize, u32),
    SizeConversionError(usize, u32),
}

pub struct Decoder<'a> {
    data: &'a [u8],
    index: usize,
}

pub trait FromXdrDecoder: Sized {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<Self, Error>;
}

impl FromXdrDecoder for bool {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<bool, Error> {
        decoder.get_bool()
    }
}

impl FromXdrDecoder for f32 {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<f32, Error> {
        decoder.get_f32()
    }
}

impl FromXdrDecoder for f64 {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<f64, Error> {
        decoder.get_f64()
    }
}

impl FromXdrDecoder for i32 {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<i32, Error> {
        decoder.get_i32()
    }
}

impl FromXdrDecoder for i64 {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<i64, Error> {
        decoder.get_i64()
    }
}

impl FromXdrDecoder for u32 {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<u32, Error> {
        decoder.get_u32()
    }
}

impl FromXdrDecoder for u64 {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<u64, Error> {
        decoder.get_u64()
    }
}

impl FromXdrDecoder for usize {
    fn from_xdr_decoder(decoder: &mut Decoder) -> Result<usize, Error> {
        decoder.get_usize()
    }
}

impl Decoder<'_> {
    /// Returns an error if need is larger than the number of bytes available.
    ///
    /// # Arguments
    ///
    /// * `need` - Number of bytes needed.
    fn check_bounds(&self, need: usize) -> Result<(), Error> {
        match self.data.len().checked_sub(self.index) {
            None => Err(Error::IndexOutOfBounds(self.index, self.data.len())),
            Some(v) => {
                if v < need {
                    Err(Error::EndOfInput(self.index, need))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Returns a 4 byte array if there are enough bytes available, else error.
    fn get_4_bytes(&self) -> Result<[u8; 4], Error> {
        self.check_bounds(4)?;
        Ok(self.data[self.index..self.index + 4].try_into().unwrap())
    }

    /// Returns an 8 byte array if there are enough bytes available, else error.
    fn get_8_bytes(&self) -> Result<[u8; 8], Error> {
        self.check_bounds(8)?;
        Ok(self.data[self.index..self.index + 8].try_into().unwrap())
    }

    /// Returns a bool if there are enough bytes available, and the value is
    /// 0 or 1, else error.
    pub fn get_bool(&mut self) -> Result<bool, Error> {
        let value = self.get_u32()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidBoolean(self.index - 4, value)),
        }
    }

    /// Returns an f32 if there are enough bytes available, else error.
    pub fn get_f32(&mut self) -> Result<f32, Error> {
        let bytes = self.get_4_bytes()?;
        Ok(f32::from_be_bytes(bytes))
    }

    /// Returns an f64 if there are enough bytes available, else error.
    pub fn get_f64(&mut self) -> Result<f64, Error> {
        let bytes = self.get_8_bytes()?;
        Ok(f64::from_be_bytes(bytes))
    }

    /// Returns an i32 if there are enough bytes available, else error.
    pub fn get_i32(&mut self) -> Result<i32, Error> {
        let bytes = self.get_4_bytes()?;
        Ok(i32::from_be_bytes(bytes))
    }

    /// Returns an i64 if there are enough bytes available, else error.
    pub fn get_i64(&mut self) -> Result<i64, Error> {
        let bytes = self.get_8_bytes()?;
        Ok(i64::from_be_bytes(bytes))
    }

    /// Returns a u32 if there are enough bytes available, else error.
    pub fn get_u32(&mut self) -> Result<u32, Error> {
        let bytes = self.get_4_bytes()?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Returns a u64 if there are enough bytes available, else error.
    pub fn get_u64(&mut self) -> Result<u64, Error> {
        let bytes = self.get_8_bytes()?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Returns a u32 converted to a usize if there are enough bytes available,
    /// else error. This is useful for arrays and strings, where the length or
    /// count is an 32 bit unsigned integer.
    pub fn get_usize(&mut self) -> Result<usize, Error> {
        let value = self.get_u32()?;
        match usize::try_from(value) {
            Ok(v) => Ok(v),
            Err(_) => Err(Error::SizeConversionError(self.index - 4, value)),
        }
    }

    /// Decode a value using the FromXdrDecoder trait for F.
    pub fn decode<F: FromXdrDecoder>(&mut self) -> Result<F, Error> {
        FromXdrDecoder::from_xdr_decoder(self)
    }

    // TODO: string
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EndOfInput(index, need) => write!(f, "xdr::Error::EndOfInput"),
            _ => write!(f, "TODO"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::xdr;
    // use crate::xdr::FromXdrDecoder;

    use std::error::Error;

    #[test]
    fn test_decoder() -> Result<(), Box<dyn Error>> {
        let data = &[0x12, 0x34, 0x56, 0x78];
        let mut decoder = xdr::Decoder {
            data: data,
            index: 0,
        };

        // let result = decoder.get_u32();
        // let result = u32::from_xdr_decoder(&mut decoder);
        let result = decoder.decode();
        let v: u32 = match result {
            Ok(v) => v,
            // Err(_) => todo!(),
            Err(e) -> println!("err: {err}", );
            // println!("err: {err}"),
        };
        println!("Value: {v}");

        return Ok(());
    }
}
