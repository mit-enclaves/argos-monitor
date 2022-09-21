#![no_std]
#![no_main]

use core::panic::PanicInfo;
use second_stage;
use second_stage::allocator::FrameAllocator;
use second_stage::debug::qemu;
use second_stage::guest::{handle_exit, init_guest, HandlerResult};
use second_stage::println;
use stage_two_abi::{add_manifest, entry_point, GuestInfo, Manifest};
use vmx::Register;

entry_point!(second_stage_entry_point);
add_manifest!();

pub extern "C" fn second_stage_entry_point(manifest: &'static Manifest) -> ! {
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    second_stage::init(manifest);
    println!("Initialization: done");
    let mut allocator = FrameAllocator::new(manifest.poffset, manifest.voffset);
    launch_guest(&mut allocator, &manifest.info);
    // Exit
    qemu::exit(qemu::ExitCode::Success);
}

fn launch_guest(allocator: &mut FrameAllocator, infos: &GuestInfo) {
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

        println!("Launching");
        let mut result = vcpu.launch();
        let mut launch = "Launch";
        let mut counter = 0;
        loop {
            let rip = vcpu.get(Register::Rip);
            let rax = vcpu.get(Register::Rax);
            let rcx = vcpu.get(Register::Rcx);
            let rbp = vcpu.get(Register::Rbp);
            println!(
                "{}: {} {:?} - rip: 0x{:x} - rbp: 0x{:x} - rax: 0x{:x} - rcx: 0x{:x}",
                launch,
                counter,
                vcpu.exit_reason(),
                rip,
                rbp,
                rax,
                rcx
            );

            let exit_reason = if let Ok(exit_reason) = result {
                handle_exit(&mut vcpu, exit_reason).expect("Failed to handle VM exit")
            } else {
                println!("VMXerror {:?}", result);
                HandlerResult::Crash
            };

            if exit_reason != HandlerResult::Resume {
                break;
            }

            // Shutdown after too many VM exits
            counter += 1;
            if counter >= 200 {
                println!("Too many iterations: stoping guest");
                break;
            }

            // Resume VM
            launch = "Resume";
            result = vcpu.resume();
        }
        println!("Info:   {:?}", vcpu.interrupt_info());
        println!(
            "Qualif: {:?}",
            vcpu.exit_qualification()
                .map(|qualif| qualif.ept_violation())
        );
    }

    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
