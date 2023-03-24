pub mod nv;

pub mod xdr;

#[macro_use]
extern crate num_derive;

// pub mod nv;
// pub use nv::DataType;
// pub mod nv;

/*
use std::io;

use std::fs::File;
use std::os::unix::prelude::FileExt;

#[derive(Debug)]
struct BlockDevice {
    file: File,
    path: String,
    block_size: u64,
    size: u64,
}

struct NVListHeader {
    encoding: u8,
    endian: u8,
    reserved_1: u8,
    reserved_2: u8,
}

struct NVList {
    header: NVListHeader,
    version: u32,
    flags: u32,
}

struct NVPair {
    name: String,
    vtype: u32,
    count: u32,
    value: [u8],
}

fn open_block_device(path: String) -> Result<BlockDevice, io::Error> {
    // Open file.
    let file = File::open(&path)?;

    // Stat file.
    let metadata = file.metadata()?;

    // Create block device.
    let dev = BlockDevice {
        file: file,
        path: path,
        // TODO(cybojanek): configure
        block_size: 4096,
        size: metadata.len()
    };

    // Check size and block size.
    if dev.size % dev.block_size != 0 {
        // TODO(cybojanek): how to return an error!?
    }

    return Ok(dev)
}

impl BlockDevice {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.file.read_at(buf, offset)
    }
}

use zfs::nv::DataType;

fn main() {
    let path = "disk.img".to_string();

    // let dev = open_block_device(path).expect("opening path failed");
    // println!("Hello {}", dev.path);
    println!("Hello {}", path);

}


*/
