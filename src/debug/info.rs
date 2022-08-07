use core::sync::atomic::AtomicU64;

#[no_mangle]
pub static GUEST_START: AtomicU64 = AtomicU64::new(0);
