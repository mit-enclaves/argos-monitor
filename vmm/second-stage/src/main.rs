#![cfg_attr(not(test), no_std)]

#[cfg(not(test))]
use core::panic::PanicInfo;
use second_stage::debug::qemu;
#[cfg(not(test))]
use second_stage::guest::{handle_exit, init_guest, HandlerResult};
use second_stage::println;
use stage_two_abi::{add_manifest, entry_point, Manifest, GuestInfo};

entry_point!(second_stage_entry_point);
add_manifest!();

pub extern "C" fn second_stage_entry_point(manifest: &'static Manifest) -> ! {
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    println!("Manifest CR3: 0x{:x}", manifest.cr3);
    second_stage::init(manifest);
    println!("Initialization: done");

    // Exit
    qemu::exit(qemu::ExitCode::Success);
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use second_stage::frame_allocator::FrameAllocator;

    #[test]
    fn test_alloc_works() {
        let mut frame_alloc = FrameAllocator::new(0, 0);
        let new_frame = frame_alloc.allocate_frame();
        assert!(new_frame.is_some());
    }

    #[test]
    fn test_alloc_when_full() {
        let mut frame_alloc = FrameAllocator::new(0, 0);
        for _ in 0..second_stage::frame_allocator::NB_PAGES {
            let new_frame = frame_alloc.allocate_frame();
            assert!(new_frame.is_some());
        }
        let new_frame = frame_alloc.allocate_frame();
        assert!(new_frame.is_none());
    }

    #[test]
    fn test_alloc_and_dealloc_several_times() {
        let mut frame_alloc = FrameAllocator::new(0, 0);
        for _ in 0..second_stage::frame_allocator::NB_PAGES * 10 {
            let new_frame = frame_alloc.allocate_frame();
            assert!(new_frame.is_some());
            unsafe {frame_alloc.deallocate_frame(new_frame.unwrap())};
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
