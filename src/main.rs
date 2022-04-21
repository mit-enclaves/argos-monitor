#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

use kernel::println;
use kernel::vmx;

use bootloader::{entry_point, BootInfo};

entry_point!(kernel_main);

#[no_mangle]
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    println!("=========== Start QEMU ===========");

    kernel::init();
    let mut _vma_allocator =  unsafe { kernel::init_memory(boot_info).expect("Failed to initialize memory") };

    println!("VMX: {:?}", vmx::vmx_available());

    // the vmxon region must be a 4kb page-aligned region.
    // let vmxon_region = vma_allocator.with_capacity(0x1000).unwrap();
    // let vmxon_addr = vmxon_region.as_phys_addr();

    // unsafe {
    //     vmx::vmxon();
    // }

    println!("Done");

    #[cfg(test)]
    test_main();

    kernel::qemu::exit(kernel::qemu::ExitCode::Success);
    kernel::hlt_loop();
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);

    kernel::qemu::exit(kernel::qemu::ExitCode::Failure);
    kernel::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel::test_panic_handler(info);
}
