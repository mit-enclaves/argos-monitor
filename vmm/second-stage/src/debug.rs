//! Debug Module
//!
//! This module is used for debugging, but is excluded from the TCB when compiling on release mode
//! (it is instead replaced by a stub module wity no-ops).

// ———————————————————————————— Print Facilities ———————————————————————————— //

#[cfg(target_arch = "x86_64")]
pub mod serial {
    use core::fmt;
    use core::fmt::Write;
    use uart_16550::SerialPort;

    /// Serial port used to log to stdout when running in Qemu.
    //  TODO: wrap port in mutex
    static mut SERIAL_PORT: SerialPort = unsafe { SerialPort::new(0x3F8) };

    /// Internal function used to print to stdout when running in Qemu.
    pub fn _print(args: fmt::Arguments) {
        // SAFETY:
        //
        // For now we are running in single-threaded mode, and the interrupts are disabled within the
        // VMM.
        unsafe {
            SERIAL_PORT
                .write_fmt(args)
                .expect("Printing to serial failed");
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub mod serial {
    use core::fmt;

    /// Internal function used to print to stdout when running in Qemu.
    pub fn _print(_args: fmt::Arguments) {
        // TODO
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::debug::serial::_print(core::format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", core::format_args!($($arg)*)));
}

// —————————————————————————————————— Qemu —————————————————————————————————— //

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum ExitCode {
    Success = 0x10,
    Failure = 0x11,
}

impl ExitCode {
    pub fn to_str(self) -> &'static str {
        match self {
            ExitCode::Success => "Success",
            ExitCode::Failure => "Failure",
        }
    }
}

pub mod qemu {
    #[cfg(target_arch = "x86_64")]
    use crate::x86_64::{exit_qemu, hlt};
    #[cfg(target_arch = "riscv64")]
    use crate::riscv::{exit_qemu, hlt};

    pub use super::ExitCode;

    pub fn exit(exit_code: ExitCode) -> ! {
        println!("========= Exiting Second Stage =========");
        println!("{}", exit_code.to_str());
        println!("========================================");

        exit_qemu(exit_code);
        hlt();
    }
}
