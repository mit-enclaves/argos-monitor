#![no_std]
#![no_main]

use core::panic::PanicInfo;
use debug;
use mmu::FrameAllocator;
use second_stage;
use second_stage::allocator::BumpAllocator;
use second_stage::debug::qemu;
use second_stage::guest::vmx::{init_guest, VmxGuest};
use second_stage::guest::Guest;
use second_stage::hypercalls::Hypercalls;
use second_stage::println;
use second_stage::statics::Statics;
use stage_two_abi::{entry_point, GuestInfo, Manifest};

entry_point!(second_stage_entry_point, Statics);

pub extern "C" fn second_stage_entry_point(manifest: &'static mut Manifest<Statics>) -> ! {
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    second_stage::init(manifest);
    println!("Initialization: done");
    let mut statics = manifest
        .statics
        .take()
        .expect("Missing statics in manifest");
    let mut allocator = BumpAllocator::new(
        manifest.poffset,
        manifest.voffset,
        statics.pages.take().expect("No pages in statics"),
    );
    let hypercalls = Hypercalls::new(&mut statics);
    launch_guest(&mut allocator, &manifest.info, hypercalls);
    // Exit
    qemu::exit(qemu::ExitCode::Success);
}

fn launch_guest(allocator: &impl FrameAllocator, infos: &GuestInfo, hypercalls: Hypercalls) {
    if !infos.loaded {
        println!("No guest found, exiting");
        return;
    }

    let frame = allocator
        .allocate_frame()
        .expect("Failed to allocate VMXON");
    unsafe {
        println!("Init the guest");
        let vmxon = match vmx::vmxon(frame) {
            Ok(vmxon) => {
                println!("VMXON: ok(vmxon)");
                vmxon
            }
            Err(err) => {
                println!("VMXON: {:?}", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
        };

        let mut vmcs = init_guest(&vmxon, allocator, infos);
        println!("Done with the guest init");
        let mut vcpu = vmcs.set_as_active().expect("Failed to activate VMCS");

        // Hook for debugging.
        debug::tyche_hook_stage2(1);

        println!("Launching");
        let mut guest = VmxGuest::new(&mut vcpu, hypercalls);
        guest.main_loop();
    }

    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
