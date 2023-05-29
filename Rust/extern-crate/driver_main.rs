// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use ext_crate::add;

module! {
    type: Driver,
    name: "driver",
    author: "Tyche team",
    description: "Rust driver with external crate",
    license: "GPL",
}

struct Driver;

impl kernel::Module for Driver {
    fn init(_name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        
        pr_info!("Hello world! (init)\n");

        let answer = add(5, 10);
        pr_info!("Answer is : {}\n", answer);


        Ok(Driver {})
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        pr_info!("Goodbye! (exit)\n");
    }
}
