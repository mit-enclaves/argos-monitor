//! Risc-V guest

use super::Arch;
use crate::statics::Statics;
use stage_two_abi::Manifest;

pub fn launch_guest(_manifest: &'static mut Manifest<Statics<Arch>>) {
    // TODO
}
