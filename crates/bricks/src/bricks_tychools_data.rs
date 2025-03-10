use crate::allocator::page_allocator::bricks_setup_allocator;
use crate::arch::bricks_transition_setup;
use crate::shared_buffer::{BRICKS_SHARED_BUFFER, BRICKS_SHARED_BUFFER_SIZE};

// Introduced by tychools
pub const BRICKS_INFO_SEGMENT: usize = BRICKS_SHARED_BUFFER + BRICKS_SHARED_BUFFER_SIZE;

// if there is something that is not u64, conversion will not work (alignment)
// easiest for everything to be u64 (8 bytes long)
#[derive(Copy, Clone)]
pub struct RuntimeData {
    memory_pool_start: u64,
    memory_pool_size: u64,
    user_rip_start: u64,
    user_stack_start: u64,
}

pub fn get_tychools_info() {
    unsafe {
        let bricks_data: RuntimeData = *(BRICKS_INFO_SEGMENT as *mut RuntimeData);
        bricks_setup_allocator(bricks_data.memory_pool_start, bricks_data.memory_pool_size);
        bricks_transition_setup(bricks_data.user_rip_start, bricks_data.user_stack_start);
    }
}
