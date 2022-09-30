//! # Statically allocated structures
//!
//! We use a `make_static` macro to define the static structures of stage 2. This macros ensures
//! that symbols are properly exposed and can be picked up by stage 1. Stage 2 get access to the
//! statics trough the manifest, which will contain a single mutable reference to those static,
//! therefore creating a safe wrapper around mutable statics.
//!
//! Important: To add a new statics, there are three steps:
//! 1. Add a new static in this file within the `make_static` macro.
//! 2. Add the name of the static in the `find_statics` macro withing the second stage ABI crate.
//! 3. Add the name of the symbol preceeded by `__` at the top of the linker script (next to other
//!    symbols). The linker script is called `second-stage-linker-script.x` and is located at the
//!    root of the repository.

use crate::allocator::{Page, NB_PAGES, PAGE_SIZE};
use stage_two_abi::make_static;

const EMPTY_PAGE: Page = Page {
    data: [0; PAGE_SIZE as usize],
};

make_static! {
    static mut pages: [Page; NB_PAGES] = [EMPTY_PAGE; NB_PAGES];
}
