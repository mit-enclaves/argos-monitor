// SPDX-License-Identifier: GPL-2.0i

//! Rust memory allocation sample

use kernel::prelude::*;
use kernel::{
    pages::Pages,
    mm::virt::Area,
    miscdev::Registration,
    file::{self, File}
};

module! {
    type: AllocationDriver,
    name: "memory_allocation",
    author: "Tyche team",
    description: "Rust memory allocation example module",
    license: "GPL",
}

struct RustFile;

#[vtable]
impl file::Operations for RustFile {
    type Data = Box<Self>;

    fn open(_shared: &(), _file: &File) -> Result<Box<Self>> {
        Ok(Box::try_new(Self {})?)
    }

    fn mmap(
        _this: &Self,
        _file: &File,
        vma: &mut Area,
    ) -> Result {
        const PAGE_SIZE : usize = 4096;

        pr_info!("Begin of mmap");
        let size = vma.end() - vma.start();
        
        // size must be positive
        if size <= 0 {
            pr_err!("End is smaller than start");
            return Err(EINVAL);
        }

        if vma.start() % PAGE_SIZE != 0 || vma.end() % PAGE_SIZE != 0 {
            pr_err!("End or/Start is/are not page-aligned.");
            return Err(EINVAL);
        }

        let page = match Pages::<0>::new() {
            Ok(p) => p,
            Err(e) => return Err(e),
        };
        
        vma.insert_page(vma.start(), &page).expect("Error at inserting page");
        
        // this must appear at the begining of the mapped address in user space
        // writing functions are unsafe
        unsafe {
            let buffer: [u8; 4] = [1, 2, 3, 4];
            page.write(buffer.as_ptr(), 0, 4).expect("Error writing to page");
        }

        pr_info!("Allocation succeed\n");
        
        Ok(())
    }
}



// module definition and registration
struct AllocationDriver {
    _dev: Pin<Box<Registration<RustFile>>>,
}


impl kernel::Module for AllocationDriver {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        pr_info!("memory_allocation: (init)\n");
        
        Ok(Self {
            _dev: Registration::new_pinned(fmt!("{name}"), ())?,
        })
    }
}

impl Drop for AllocationDriver {
    fn drop(&mut self) {
        pr_info!("memory_allocation: (exit)\n");
    }
}
