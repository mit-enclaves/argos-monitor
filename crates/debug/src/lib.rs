//! Debug hooks for Tyche dev.

#![no_std]

use core::assert;
use core::sync::atomic::{AtomicU64, Ordering};

#[no_mangle]
pub static STAGE2_POFF: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub static STAGE2_VOFF: AtomicU64 = AtomicU64::new(0);

pub fn hook_stage2_offsets(phys: u64, virt: u64) {
    STAGE2_POFF.store(phys, Ordering::Relaxed);
    STAGE2_VOFF.store(virt, Ordering::Relaxed);
}

/// Hook to break on in stage 1
pub fn tyche_hook_stage1(val: u64) {
    assert!(val != 0);
}

/// Hook to break on in stage 2
pub fn tyche_hook_stage2(val: u64) {
    assert!(val != 0);
}

/// Hook to break on in stage 2
pub fn tyche_hook_main_loop(val: u64) {
    assert!(val != 0);
}


pub fn tyche_hook_error(val: u64) {
    assert!(val != 0);
}