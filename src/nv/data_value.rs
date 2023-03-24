// NV Pair Data Value.
#[derive(Debug)]
pub enum DataValue<'a> {
    Boolean(bool),

    Byte(u8),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    String(String),

    ByteArray(&'a[u8]),
    Int16Array(&'a[i16]),
    Uint16Array(&'a[u16]),
    Int32Array(&'a[i32]),
    Uint32Array(&'a[u32]),
    Int64Array(&'a[i64]),
    Uint64Array(&'a[u64]),
    StringArray(&'a[String]),

    // HrTime,

    // NvList(NvList),
    // NvListArray([]NvList),

    Int8(i8),
    Uint8(u8),

    BooleanArray(&'a[bool]),
    Int8Array(&'a[i8]),
    Uint8Array(&'a[u8]),

    Double(f64),
}
