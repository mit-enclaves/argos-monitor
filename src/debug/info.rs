use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

#[no_mangle]
pub static GUEST_START: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub static GUEST_STACK_PHYS: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub static GUEST_STACK_VIRT: AtomicU64 = AtomicU64::new(0);

pub fn tyche_hook_set_guest_start(val: u64) {
    GUEST_START.store(val, Ordering::Relaxed);
}

pub fn hook_set_guest_stack(phys: u64, virt: u64) {
    GUEST_STACK_PHYS.store(phys, Ordering::Relaxed);
    GUEST_STACK_VIRT.store(virt, Ordering::Relaxed);
}

/// This is not doing anything, we just use it for debugging to break on
pub fn tyche_hook_done(val: u64) {
    assert!(val != 0);
}
