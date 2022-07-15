//! Elf Definitions
//!
//! Mostly copied from:
//! https://github.com/rust-vmm/linux-loader/blob/ca135832b6c9108c8447a023f4c715bf9161fab9/src/loader_gen/x86_64/elf.rs

mod ffi {
    #![allow(non_camel_case_types)]

    use core::ffi;

    pub type __s8 = ffi::c_schar;
    pub type __u8 = ffi::c_uchar;
    pub type __s16 = ffi::c_short;
    pub type __u16 = ffi::c_ushort;
    pub type __s32 = ffi::c_int;
    pub type __u32 = ffi::c_uint;
    pub type __s64 = ffi::c_longlong;
    pub type __u64 = ffi::c_ulonglong;

    pub type Elf64_Addr = __u64;
    pub type Elf64_Half = __u16;
    pub type Elf64_Off = __u64;
    pub type Elf64_Word = __u32;
    pub type Elf64_Xword = __u64;

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct Elf64Hdr {
        pub e_ident: [__u8; 16usize],
        pub e_type: Elf64_Half,
        pub e_machine: Elf64_Half,
        pub e_version: Elf64_Word,
        pub e_entry: Elf64_Addr,
        pub e_phoff: Elf64_Off,
        pub e_shoff: Elf64_Off,
        pub e_flags: Elf64_Word,
        pub e_ehsize: Elf64_Half,
        pub e_phentsize: Elf64_Half,
        pub e_phnum: Elf64_Half,
        pub e_shentsize: Elf64_Half,
        pub e_shnum: Elf64_Half,
        pub e_shstrndx: Elf64_Half,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct Elf64Phdr {
        pub p_type: Elf64_Word,
        pub p_flags: Elf64_Word,
        pub p_offset: Elf64_Off,
        pub p_vaddr: Elf64_Addr,
        pub p_paddr: Elf64_Addr,
        pub p_filesz: Elf64_Xword,
        pub p_memsz: Elf64_Xword,
        pub p_align: Elf64_Xword,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct Elf64Shdr {
        pub sh_name: Elf64_Word,
        pub sh_type: Elf64_Word,
        pub sh_flags: Elf64_Xword,
        pub sh_addr: Elf64_Addr,
        pub sh_offset: Elf64_Off,
        pub sh_size: Elf64_Xword,
        pub sh_link: Elf64_Word,
        pub sh_addralign: Elf64_Xword,
        pub sh_entsize: Elf64_Xword,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct Elf64Note {
        pub n_namesz: Elf64_Word,
        pub n_descsz: Elf64_Word,
        pub n_type: Elf64_Word,
    }
}

use core::mem;

use bitflags::bitflags;
pub use ffi::{Elf64Hdr, Elf64Note, Elf64Phdr};

use self::ffi::Elf64Shdr;

bitflags! {
    /// Valid values for the Elf64Phdr.p_type entry.
    pub struct Elf64PhdrType : ffi::Elf64_Word {
        const PT_NULL       = 0x0;          // program header entry unused.
        const PT_LOAD       = 0x1;          // loadable segment.
        const PT_DYNAMIC    = 0x2;          // dynamic linking information.
        const PT_INTERP     = 0x3;          // interpreter information.
        const PT_NOTE       = 0x4;          // auxiliary information.
        const PT_SHLIB      = 0x5;          // reserved.
        const PT_PHDR       = 0x6;          // prog header segment.
        const PT_TLS        = 0x7;          // thread-local storage.
        const PT_LOOS       = 0x60000000;   // reserved INCLUSIVE range OS.
        const PT_HIOS       = 0x6FFFFFFF;   // |
        const PT_LOPROC     = 0x70000000;   // reserved INCLUSIVE range Proc.
        const PT_HIPROC     = 0x7FFFFFFF;   // |
    }

    pub struct Elf64PhdrFlags: ffi::Elf64_Word {
        const PF_X          = 0x1;          // Execute.
        const PF_W          = 0x2;          // Write.
        const PF_R          = 0x4;          // Read.
        const PF_MASKPROC   = 0xf0000000;   // Unspecified.
    }
}

/// Types that can be read from raw bytes.
///
/// SAFETY: This trait must be implemented only on types that contains plain value. Implememting
/// this trait on a type that contains pointers or references (even nested in other structs) leads
/// to undefined behavior.
pub unsafe trait FromBytes: Sized + Clone {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        // Safety: The trait must be implememted only for struct that don't contain pointers or
        // reference, and a lenght check was performed just above.
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some((&*ptr).clone())
        }
    }
}

unsafe impl FromBytes for Elf64Note {}
unsafe impl FromBytes for Elf64Phdr {}
unsafe impl FromBytes for Elf64Hdr {}
unsafe impl FromBytes for Elf64Shdr {}
