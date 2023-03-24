extern crate zfs;

// use zfs::nv::DataType;
use zfs::nv;

fn main() {
    // let data_type = DataType::Boolean;
    let data_type = nv::DataType::Boolean;
    println!("DataType is: {:#?}", data_type);

    let data_value = nv::DataValue::Boolean(true);
    println!("DataValue is: {:#?}", data_value);
}
