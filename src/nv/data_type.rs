extern crate num;
extern crate strum;

// NV Pair Data Type.
#[derive(Debug, FromPrimitive, strum::Display, PartialEq)]
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

    Int8,
    Uint8,

    BooleanArray,
    Int8Array,
    Uint8Array,

    Double,
}

#[cfg(test)]
mod tests {
    use crate::nv::DataType;

    #[test]
    fn test_data_type() {
        assert_eq!(DataType::Boolean as u32, 1);

        assert_eq!(DataType::Byte as u32, 2);
        assert_eq!(DataType::Int16 as u32, 3);
        assert_eq!(DataType::Uint16 as u32, 4);
        assert_eq!(DataType::Int32 as u32, 5);
        assert_eq!(DataType::Uint32 as u32, 6);
        assert_eq!(DataType::Int64 as u32, 7);
        assert_eq!(DataType::Uint64 as u32, 8);
        assert_eq!(DataType::String as u32, 9);

        assert_eq!(DataType::ByteArray as u32, 10);
        assert_eq!(DataType::Int16Array as u32, 11);
        assert_eq!(DataType::Uint16Array as u32, 12);
        assert_eq!(DataType::Int32Array as u32, 13);
        assert_eq!(DataType::Uint32Array as u32, 14);
        assert_eq!(DataType::Int64Array as u32, 15);
        assert_eq!(DataType::Uint64Array as u32, 16);
        assert_eq!(DataType::StringArray as u32, 17);

        assert_eq!(DataType::HrTime as u32, 18);
        assert_eq!(DataType::NvList as u32, 19);
        assert_eq!(DataType::NvListArray as u32, 20);

        assert_eq!(DataType::Int8 as u32, 21);
        assert_eq!(DataType::Uint8 as u32, 22);

        assert_eq!(DataType::BooleanArray as u32, 23);
        assert_eq!(DataType::Int8Array as u32, 24);
        assert_eq!(DataType::Uint8Array as u32, 25);

        assert_eq!(DataType::Double as u32, 26);
    }
}
