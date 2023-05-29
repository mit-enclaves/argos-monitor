// SPDX-License-Identifier: GPL-2.0i

//! Rust ioctl-example sample

use core::sync::atomic::{AtomicU64, Ordering};
use kernel::prelude::*;
use kernel::{
    miscdev::Registration,
    file::{self, File, IoctlCommand, IoctlHandler},
    io_buffer::{IoBufferReader, IoBufferWriter},
    user_ptr::{UserSlicePtrReader, UserSlicePtrWriter}
};

module! {
    type: IOCTLDriver,
    name: "ioctl_example",
    author: "Tyche team",
    description: "Rust ioctl example module",
    license: "GPL",
}

struct RustFile {
    count: AtomicU64,
}

#[vtable]
impl file::Operations for RustFile {
    type Data = Box<Self>;

    fn open(_shared: &(), _file: &File) -> Result<Box<Self>> {
        Ok(Box::try_new(Self {count: AtomicU64::new(0)})?)
    }

    fn read(_this: &Self, _: &File, _data: &mut impl IoBufferWriter, _offs: u64) -> Result<usize> {
        Ok(1)
    }

    fn write(_this: &Self, _: &File, data: &mut impl IoBufferReader, _offs: u64) -> Result<usize> {
        Ok(data.len())
    }

    fn ioctl(this: &Self, file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        cmd.dispatch::<Self>(this, file)
    }
}



// module definition and registration
struct IOCTLDriver {
    _dev: Pin<Box<Registration<RustFile>>>,
}


impl kernel::Module for IOCTLDriver {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("ioctl_driver: (init)\n");
        
        Ok(Self {
            _dev: Registration::new_pinned(fmt!("{name}"), ())?,
        })
    }
}

impl Drop for IOCTLDriver {
    fn drop(&mut self) {
        pr_info!("ioctl_driver: (exit)\n");
    }
}




const IOCTL_PURE_PRINT_VALUE: u32 = 1;
const IOCTL_GET: u32 = 0;
const IOCTL_SET: u32 = 1;

impl IoctlHandler for RustFile {
    type Target<'a> = &'a Self;
    
    fn pure(_this: Self::Target<'_>, _file: &File, cmd: u32, arg: usize) -> Result<i32> {
        match cmd {
            IOCTL_PURE_PRINT_VALUE =>{
                pr_info!("driver received value {}\n", arg as u32);
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }

    fn read(this: &Self, _: &File, cmd: u32, writer: &mut UserSlicePtrWriter) -> Result<i32> {
        match cmd {
            IOCTL_GET => {
                pr_info!("current value of count: {}\n", this.count.load(Ordering::Relaxed));
                writer.write(&this.count.load(Ordering::Relaxed))?;
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }

    fn write(this: &Self, _: &File, cmd: u32, reader: &mut UserSlicePtrReader) -> Result<i32> {
        match cmd {
            IOCTL_SET => {
                this.count.store(reader.read()?, Ordering::Relaxed);
                pr_info!("new value of count: {}\n", this.count.load(Ordering::Relaxed));
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }
}
