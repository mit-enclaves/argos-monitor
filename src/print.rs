//! Printing utilities
//!
//! This modules enables printing on different devices, depending on the features selected at
//! compilation time.

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        if cfg!(feature = "vga") {
            $crate::vga::_print(core::format_args!($($arg)*))
        } else {
            $crate::serial::_print(core::format_args!($($arg)*))
        }
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", core::format_args!($($arg)*)))
}

