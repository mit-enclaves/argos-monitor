#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use kernel::println;
use kernel::qemu;
use kernel::vmx;

use bootloader::{entry_point, BootInfo};

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static BootInfo) -> ! {
    println!("=========== Start QEMU ===========");

    kernel::init();
    let vma_allocator =
        unsafe { kernel::init_memory(boot_info).expect("Failed to initialize memory") };

    unsafe {
        println!("VMX:    {:?}", vmx::vmx_available());
        println!("VMXON:  {:?}", vmx::vmxon(&vma_allocator));

        let mut vmcs = match vmx::VmcsRegion::new(&vma_allocator) {
            Err(err) => {
                println!("VMCS:   Err({:?})", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
            Ok(vmcs) => {
                println!("VMCS:   Ok(())");
                vmcs
            }
        };

        println!("LOAD:   {:?}", vmcs.set_as_active());
        println!(
            "Ctrls1: {:?}",
            vmcs.set_pin_based_ctls(vmx::PinbasedControls::empty())
        );
        println!("VMXOFF: {:?}", vmx::vmxoff());
    }

    #[cfg(test)]
    test_main();

    kernel::qemu::exit(kernel::qemu::ExitCode::Success);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);

    kernel::qemu::exit(kernel::qemu::ExitCode::Failure);
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel::test_panic_handler(info);
}
