//! Risc-V guest

use crate::hypercalls::{Backend, Hypercalls};
use mmu::FrameAllocator;
use stage_two_abi::GuestInfo;

pub fn launch_guest(
    _allocator: &impl FrameAllocator,
    _infos: &GuestInfo,
    _hypercalls: Hypercalls<impl Backend>,
) {
    // TODO
}
