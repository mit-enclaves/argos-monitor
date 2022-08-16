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
    pub struct Elf64Sym {
        pub st_name: Elf64_Word,
        pub st_info: __u8,
        pub st_other: __u8,
        pub st_shndx: Elf64_Half,
        pub st_value: Elf64_Addr,
        pub st_size: Elf64_Xword,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct Elf64Note {
        pub n_namesz: Elf64_Word,
        pub n_descsz: Elf64_Word,
        pub n_type: Elf64_Word,
    }

    /// Linux boot related structures.
    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    struct ScreenInfo {
        orig_x: __u8,             /* 0x00 */
        orig_y: __u8,             /* 0x01 */
        ext_mem_k: __u16,         /* 0x02 */
        orig_video_page: __u16,   /* 0x04 */
        orig_video_mode: __u8,    /* 0x06 */
        orig_video_cols: __u8,    /* 0x07 */
        flags: __u8,              /* 0x08 */
        unused2: __u8,            /* 0x09 */
        orig_video_ega_bx: __u16, /* 0x0a */
        unused3: __u16,           /* 0x0c */
        orig_video_lines: __u8,   /* 0x0e */
        orig_video_is_vga: __u8,  /* 0x0f */
        orig_video_points: __u16, /* 0x10 */

        /* VESA graphic mode -- linear frame buffer */
        lfb_width: __u16,  /* 0x12 */
        lfb_height: __u16, /* 0x14 */
        lfb_depth: __u16,  /* 0x16 */
        lfb_base: __u32,   /* 0x18 */
        lfb_size: __u32,   /* 0x1c */
        cl_magic: __u16,   /* 0x20 */
        cl_offset: __u16,
        lfb_linelength: __u16,  /* 0x24 */
        red_size: __u8,         /* 0x26 */
        red_pos: __u8,          /* 0x27 */
        green_size: __u8,       /* 0x28 */
        green_pos: __u8,        /* 0x29 */
        blue_size: __u8,        /* 0x2a */
        blue_pos: __u8,         /* 0x2b */
        rsvd_size: __u8,        /* 0x2c */
        rsvd_pos: __u8,         /* 0x2d */
        vesapm_seg: __u16,      /* 0x2e */
        vesapm_off: __u16,      /* 0x30 */
        pages: __u16,           /* 0x32 */
        vesa_attributes: __u16, /* 0x34 */
        capabilities: __u32,    /* 0x36 */
        ext_lfb_base: __u32,    /* 0x3a */
        _reserved: [__u8; 2],   /* 0x3e */
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    struct ApmBiosInfo {
        version: __u16,
        cseg: __u16,
        offset: __u32,
        cseg_16: __u16,
        dseg: __u16,
        flags: __u16,
        cseg_len: __u16,
        cseg_16_len: __u16,
        dseg_len: __u16,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    struct IstInfo {
        signature: __u32,
        command: __u32,
        event: __u32,
        perf_level: __u32,
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    struct SysDescTable {
        length: __u16,
        table: [__u8; 14],
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    struct OlpcOfwHeader {
        ofw_magic: __u32, /* OFW signature */
        ofw_version: __u32,
        cif_handler: __u32, /* callback into OFW */
        irq_desc_table: __u32,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct EdidInfo {
        dummy: [__u8; 128],
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    struct EfiInfo {
        efi_loader_signature: __u32,
        efi_systab: __u32,
        efi_memdesc_size: __u32,
        efi_memdesc_version: __u32,
        efi_memmap: __u32,
        efi_memmap_size: __u32,
        efi_systab_hi: __u32,
        efi_memmap_hi: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct SetupHeader {
        pub setup_sects: __u8,
        pub root_flags: __u16,
        pub syssize: __u32,
        pub ram_size: __u16,
        pub vid_mode: __u16,
        pub root_dev: __u16,
        pub boot_flag: __u16,
        pub jump: __u16,
        pub header: __u32,
        pub version: __u16,
        pub realmode_swtch: __u32,
        pub start_sys_seg: __u16,
        pub kernel_version: __u16,
        pub type_of_loader: __u8,
        pub loadflags: __u8,
        pub setup_move_size: __u16,
        pub code32_start: __u32,
        pub ramdisk_image: __u32,
        pub ramdisk_size: __u32,
        pub bootsect_kludge: __u32,
        pub heap_end_ptr: __u16,
        pub ext_loader_ver: __u8,
        pub ext_loader_type: __u8,
        pub cmd_line_ptr: __u32,
        pub initrd_addr_max: __u32,
        pub kernel_alignment: __u32,
        pub relocatable_kernel: __u8,
        pub min_alignment: __u8,
        pub xloadflags: __u16,
        pub cmdline_size: __u32,
        pub hardware_subarch: __u32,
        pub hardware_subarch_data: __u64,
        pub payload_offset: __u32,
        pub payload_length: __u32,
        pub setup_data: __u64,
        pub pref_address: __u64,
        pub init_size: __u32,
        pub handover_offset: __u32,
        pub kernel_info_offset: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct BootE820Entry {
        addr: __u64,
        size: __u64,
        tpe: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct ISA {
        base_address: __u16,
        reserved1: __u16,
        reserved2: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct PCI {
        bus: __u8,
        slot: __u8,
        function: __u8,
        channel: __u8,
        reserved: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct S1 {
        reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    union InterfacePath {
        isa: ISA,
        pci: PCI,
        ibnd: S1,
        xprs: S1,
        htpt: S1,
        unknown: S1,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct ATA {
        device: __u8,
        reserved1: __u8,
        reserved2: __u16,
        reserved3: __u32,
        reserved4: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct ATAPI {
        device: __u8,
        lun: __u8,
        reserved1: __u8,
        reserved2: __u8,
        reserved3: __u32,
        reserved4: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct SCSI {
        id: __u16,
        lun: __u64,
        reserved1: __u16,
        reserved2: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct USB {
        serial_number: __u64,
        reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct I1394 {
        eui: __u64,
        reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct FIBRE {
        wwid: __u64,
        lun: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct I2O {
        identity_tag: __u64,
        reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct RAID {
        array_number: __u32,
        reserved1: __u32,
        reserved2: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct SATA {
        device: __u8,
        reserved1: __u8,
        reserved2: __u16,
        reserved3: __u32,
        reserved4: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    struct UNKNOWN {
        reserved1: __u64,
        reserved2: __u64,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    union DevicePath {
        ata: ATA,
        atapi: ATAPI,
        scsi: SCSI,
        usb: USB,
        i1394: I1394,
        fibre: FIBRE,
        i2o: I2O,
        raid: RAID,
        sata: SATA,
        unknown: UNKNOWN,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct edd_device_params {
        length: __u16,
        info_flags: __u16,
        num_default_cylinders: __u32,
        num_default_heads: __u32,
        sectors_per_track: __u32,
        number_of_sectors: __u64,
        bytes_per_sector: __u16,
        dpte_ptr: __u32,               /* 0xFFFFFFFF for our purposes */
        key: __u16,                    /* = 0xBEDD */
        device_path_info_length: __u8, /* = 44 */
        reserved2: __u8,
        reserved3: __u16,
        host_bus_type: [__u8; 4],
        interface_type: [__u8; 8],
        interface_path: InterfacePath,
        device_path: DevicePath,
        reserved4: __u8,
        checksum: __u8,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct EddInfo {
        device: __u8,
        version: __u8,
        interface_support: __u16,
        legacy_max_cylinder: __u16,
        legacy_max_head: __u8,
        legacy_sectors_per_track: __u8,
        params: edd_device_params,
    }

    /* max number of signatures to store */
    const EDD_MBR_SIG_MAX: usize = 16;

    /* number of edd_info structs starting at EDDBUF  */
    const EDDMAXNR: usize = 6;

    /*
     * This is the maximum number of entries in struct boot_params::e820_table
     * (the zeropage), which is part of the x86 boot protocol ABI:
     */
    const E820_MAX_ENTRIES_ZEROPAGE: usize = 128;

    /* The so-called "zeropage" */
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct BootParams {
        screen_info: ScreenInfo,    /* 0x000 */
        apm_bios_info: ApmBiosInfo, /* 0x040 */
        _pad2: [__u8; 4],           /* 0x054 */
        tboot_addr: __u64,          /* 0x058 */
        ist_info: IstInfo,          /* 0x060 */
        acpi_rsdp_addr: __u64,      /* 0x070 */
        _pad3: [__u8; 8],           /* 0x078 */
        hd0_info: [__u8; 16],       /* obsolete! */
        /* 0x080 */
        hd1_info: [__u8; 16], /* obsolete! */
        /* 0x090 */
        sys_desc_table: SysDescTable, /* obsolete! */
        /* 0x0a0 */
        olpc_ofw_header: OlpcOfwHeader, /* 0x0b0 */
        ext_ramdisk_image: __u32,       /* 0x0c0 */
        ext_ramdisk_size: __u32,        /* 0x0c4 */
        ext_cmd_line_ptr: __u32,        /* 0x0c8 */
        _pad4: [__u8; 116],             /* 0x0cc */
        edid_info: EdidInfo,            /* 0x140 */
        efi_info: EfiInfo,              /* 0x1c0 */
        alt_mem_k: __u32,               /* 0x1e0 */
        scratch: __u32,                 /* Scratch field! */
        /* 0x1e4 */
        e820_entries: __u8,            /* 0x1e8 */
        eddbuf_entries: __u8,          /* 0x1e9 */
        edd_mbr_sig_buf_entries: __u8, /* 0x1ea */
        kbd_status: __u8,              /* 0x1eb */
        secure_boot: __u8,             /* 0x1ec */
        _pad5: [__u8; 2],              /* 0x1ed */
        /*
         * The sentinel is set to a nonzero value (0xff) in header.S.
         *
         * A bootloader is supposed to only take setup_header and put
         * it into a clean boot_params buffer. If it turns out that
         * it is clumsy or too generous with the buffer, it most
         * probably will pick up the sentinel variable too. The fact
         * that this variable then is still 0xff will let kernel
         * know that some variables in boot_params are invalid and
         * kernel should zero out certain portions of boot_params.
         */
        _sentinel: __u8,  /* 0x1ef */
        _pad6: [__u8; 1], /* 0x1f0 */
        hdr: SetupHeader, /* setup header */
        /* 0x1f1 */
        _pad7: [__u8; 0x290 - 0x1f1 - 0x7b], //  0x7f is supposed to be setup header size
        edd_mbr_sig_buffer: [__u32; EDD_MBR_SIG_MAX], /* 0x290 */
        e820_table: [BootE820Entry; E820_MAX_ENTRIES_ZEROPAGE], /* 0x2d0 */
        _pad8: [__u8; 48],                   /* 0xcd0 */
        eddbuf: [EddInfo; EDDMAXNR],         /* 0xd00 */
        _pad9: [__u8; 276],                  /* 0xeec */
    }
}

use core::mem;

use bitflags::bitflags;
pub use ffi::{Elf64Hdr, Elf64Note, Elf64Phdr, Elf64Shdr, Elf64Sym, SetupHeader};

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

    pub struct Elf64ShdrType: ffi::Elf64_Word {
        const SHT_NULL = 0x0; // section header table entry unused.
        const SHT_PROGBITS = 0x1; // program data.
        const SHT_SYMTAB = 0x2; // symbol table.
        const SHT_STRTAB = 0x3; // string table.
        const SHT_RELA = 0x4; // relocation entries with addends.
        const SHT_HASH = 0x5; // symbol hash table.
        const SHT_DYNAMIC = 0x6; // dynamic linking information.
        const SHT_NOTE = 0x7; // notes.
        const SHT_NOBITS = 0x8; // program space with no data (bss).
        const SHT_REL = 0x9; // relocation entries, no addends.
        const SHT_SHLIB = 0xA; // reserved.
        const SHT_DYNSYM = 0xB; // dynamic linker symbol table.
        const SHT_INIT_ARRAY = 0xE; // array of constructors.
        const SHT_FINI_ARRAY = 0xF; // array of destructors.
        const SHT_PREINIT_ARRAY = 0x10; // array of pre-constructors.
        const SHT_GROUP = 0x11; // section group.
        const SHT_SYMTAB_SHNDX = 0x12; // extended section indicies.
        const SHT_NUM = 0x13; // number of defined types.
        const SHT_LOOS = 0x60000000; // start OS-specific.
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
            Some(ptr.read_unaligned())
        }
    }
}

unsafe impl FromBytes for Elf64Note {}
unsafe impl FromBytes for Elf64Phdr {}
unsafe impl FromBytes for Elf64Hdr {}
unsafe impl FromBytes for Elf64Shdr {}
unsafe impl FromBytes for Elf64Sym {}
unsafe impl FromBytes for SetupHeader {}
