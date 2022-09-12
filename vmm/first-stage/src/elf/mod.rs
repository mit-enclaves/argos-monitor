//! Executable and Linkable Format - ELF

mod ffi;

use alloc::vec::Vec;
use core::str::from_utf8;

use crate::debug::info;
use crate::mmu::{FrameAllocator, PtFlag, PtMapper};
use crate::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};
pub use ffi::{
    Elf64Hdr, Elf64Phdr, Elf64PhdrFlags, Elf64PhdrType, Elf64Shdr, Elf64ShdrType, Elf64Sym,
    FromBytes,
};

pub enum ElfMapping {
    /// Respect the virtual-to-physical mapping of the ELF file.
    ElfDefault,
    /// Use an identity mapping, i.e. virtual addresses becomes equal to physical addresses.
    Identity,
}

/// An ELF program that can be loaded as a guest.
pub struct ElfProgram {
    /// The entry point, as a guest virtual address.
    pub entry: GuestVirtAddr,
    /// The entry point, as a guest physical address.
    ///
    /// To be used with identity mapping.
    pub phys_entry: GuestPhysAddr,
    pub segments: Vec<Elf64Phdr>,
    pub sections: Vec<Elf64Shdr>,
    pub bytes: &'static [u8],
    mapping: ElfMapping,
    stack: Option<(GuestVirtAddr, usize)>,
}

pub struct LoadedElf {
    /// The root of initial page tables.
    pub pt_root: GuestPhysAddr,
    /// An allocator that can be used to write data to the guest address space before launch.
    host_physical_offset: HostVirtAddr,
}

impl ElfProgram {
    /// Parses an elf program from raw bytes.
    ///
    /// Uses the ELF virtual-to-physical mappings by default.
    pub fn new(bytes: &'static [u8]) -> Self {
        let mut start: usize = 0;
        let mut end: usize = Elf64Hdr::SIZE;
        let header = Elf64Hdr::from_bytes(&bytes[start..end]).expect("header");

        // Parse all the program header entries.
        start = header.e_phoff as usize;
        end = start + (header.e_phentsize as usize);
        let mut prog_headers = Vec::<Elf64Phdr>::new();
        for _i in 0..header.e_phnum {
            let pheader = Elf64Phdr::from_bytes(&bytes[start..end]).expect("parsing prog header");
            prog_headers.push(pheader);
            start = end;
            end += header.e_phentsize as usize;
        }

        // Find entry virtual address
        let mut entry = None;
        let phys_entry = header.e_entry;
        for header in &prog_headers {
            let segment_start = header.p_paddr;
            let segment_end = segment_start + header.p_memsz;
            if phys_entry >= segment_start && phys_entry < segment_end {
                let segment_offset = phys_entry - segment_start;
                entry = Some(header.p_vaddr + segment_offset);
            }
        }
        let entry = entry.expect("Couldn't find guest entry point");

        // Parse section header table: this is needed to access symbols.
        let mut sections = Vec::<Elf64Shdr>::new();
        let shdr_start = header.e_shoff as usize;
        assert!(header.e_shentsize as usize == Elf64Shdr::SIZE);
        for i in 0..header.e_shnum {
            let start = shdr_start + (i as usize) * Elf64Shdr::SIZE;
            let end = start + Elf64Shdr::SIZE;
            let section =
                Elf64Shdr::from_bytes(&bytes[start..end]).expect("parsing section header");
            sections.push(section);
        }

        Self {
            entry: GuestVirtAddr::new(entry as usize),
            phys_entry: GuestPhysAddr::new(phys_entry as usize),
            segments: prog_headers,
            sections,
            mapping: ElfMapping::ElfDefault,
            stack: None,
            bytes,
        }
    }

    /// Configures the mappings for this program.
    pub fn set_mapping(&mut self, mapping: ElfMapping) {
        self.mapping = mapping;
    }

    /// Configures the guest stack.
    pub fn add_stack(&mut self, virt_addr: GuestVirtAddr, size: usize) {
        self.stack = Some((virt_addr, size));
    }

    /// Loads the guest program and setup the page table inside the guest memory.
    ///
    /// On success, returns the guest physical address of the guest page table root (to bet set as
    /// CR3).
    pub fn load(
        &self,
        guest_allocator: &impl FrameAllocator,
        host_physical_offset: HostVirtAddr,
    ) -> Result<LoadedElf, ()> {
        // Compute the highest physical address used by the guest.
        // The remaining space can be used to allocate page tables.
        let mut highest_addr = 0;
        for seg in self.segments.iter() {
            if seg.p_type != Elf64PhdrType::PT_LOAD.bits() {
                continue;
            }
            highest_addr = core::cmp::max(highest_addr, seg.p_paddr + seg.p_memsz);
        }

        let pt_root = guest_allocator.allocate_frame().ok_or(())?.zeroed();
        let pt_root_guest_phys_addr = GuestPhysAddr::new(pt_root.phys_addr.as_usize());
        let mut pt_mapper =
            PtMapper::new(host_physical_offset.as_usize(), 0, pt_root_guest_phys_addr);

        // Load and map segments
        for seg in self.segments.iter() {
            if seg.p_type != Elf64PhdrType::PT_LOAD.bits() {
                // Skip non-load segments.
                continue;
            }
            unsafe {
                // TODO: ensure that the segment does not overlap host memory
                self.load_segment(seg, host_physical_offset);
                self.map_segment(seg, &mut pt_mapper, guest_allocator);
            }
        }

        // Create stack, if required
        if let Some((stack_address, size)) = self.stack {
            // TODO: properly choose a valid stack physical address. Zero is not ideal...
            let stack_prot = PtFlag::WRITE | PtFlag::PRESENT | PtFlag::EXEC_DISABLE | PtFlag::USER;
            let range = guest_allocator
                .allocate_range(size)
                .expect("Failed to allocate");
            pt_mapper.map_range(
                guest_allocator,
                stack_address,
                GuestPhysAddr::new(range.start.as_usize()),
                size,
                stack_prot,
            );
            info::hook_set_guest_stack(range.start.as_u64(), stack_address.as_u64());
        }

        Ok(LoadedElf {
            pt_root: pt_root_guest_phys_addr,
            host_physical_offset,
        })
    }

    pub fn find_symbol(&self, target: &str) -> Option<Elf64Sym> {
        if self.sections.len() == 0 {
            return None;
        }
        let symbols_secs = self.find_section(Elf64ShdrType::SHT_SYMTAB);
        let strings = self.find_section(Elf64ShdrType::SHT_STRTAB);
        for sym in symbols_secs.iter() {
            for str_values in strings.iter() {
                if let Some(symbol) = self.find_symbol_helper(target, sym, str_values) {
                    return Some(symbol);
                }
            }
        }
        return None;
    }

    pub fn find_symbol_helper(
        &self,
        target: &str,
        symbols: &Elf64Shdr,
        strings: &Elf64Shdr,
    ) -> Option<Elf64Sym> {
        if self.sections.len() == 0 {
            return None;
        }

        // Find the symbol table sections.
        //let symbols = self.find_section(Elf64ShdrType::SHT_SYMTAB)?;

        // Find the string table.
        // This could be obtained directly from elf header.
        //let strings = self.find_section(Elf64ShdrType::SHT_STRTAB)?;

        let str_start = strings.sh_offset as usize;
        let str_end = str_start + strings.sh_size as usize;
        let content = &self.bytes[str_start..str_end];

        // Now look for the symbol
        if symbols.sh_size == 0 || symbols.sh_entsize == 0 {
            return None;
        }
        assert!(symbols.sh_entsize as usize == Elf64Sym::SIZE);
        // Read all the entries now.
        let nb = symbols.sh_size / symbols.sh_entsize;
        let off = symbols.sh_offset;
        for i in 0..nb {
            let start = (off + i * symbols.sh_entsize) as usize;
            let end = start + symbols.sh_entsize as usize;
            let symbol = Elf64Sym::from_bytes(&self.bytes[start..end]).expect("parsing symbol");
            if symbol.st_name == 0 || symbol.st_name as usize > content.len() {
                continue;
            }
            let n_start = symbol.st_name as usize;
            let idx = self.find_substring(&content[n_start..])?;
            let name = from_utf8(&content[n_start..(n_start + idx)]).expect("parsing name");
            // Now find the name for this symbol.
            if name == target {
                return Some(symbol);
            }
        }
        return None;
    }

    fn find_substring(&self, content: &[u8]) -> Option<usize> {
        for (i, &v) in content.iter().enumerate() {
            if v == b'\0' {
                return Some(i);
            }
        }
        return None;
    }

    fn find_section(&self, tpe: Elf64ShdrType) -> Vec<&Elf64Shdr> {
        let mut result = Vec::<&Elf64Shdr>::new();
        for sec in self.sections.iter() {
            if sec.sh_type == tpe.bits() {
                result.push(&sec);
            }
        }
        return result;
    }

    /// Maps an elf segment at the desired virtual address.
    unsafe fn map_segment(
        &self,
        segment: &Elf64Phdr,
        mapper: &mut PtMapper<GuestPhysAddr, GuestVirtAddr>,
        guest_allocator: &impl FrameAllocator,
    ) {
        match self.mapping {
            ElfMapping::ElfDefault => {
                mapper.map_range(
                    guest_allocator,
                    GuestVirtAddr::new(segment.p_vaddr as usize),
                    GuestPhysAddr::new(segment.p_paddr as usize),
                    segment.p_memsz as usize,
                    flags_to_prot(segment.p_flags),
                );
            }
            ElfMapping::Identity => {
                mapper.map_range(
                    guest_allocator,
                    GuestVirtAddr::new(segment.p_paddr as usize),
                    GuestPhysAddr::new(segment.p_paddr as usize),
                    segment.p_memsz as usize,
                    flags_to_prot(segment.p_flags),
                );
            }
        }
    }

    /// Loads an elf segment at the desired physical address.
    unsafe fn load_segment(&self, segment: &Elf64Phdr, host_physical_offset: HostVirtAddr) {
        // Sanity checks
        assert!(segment.p_align >= 0x1000);
        assert!(segment.p_memsz >= segment.p_filesz);
        assert!(segment.p_offset + segment.p_filesz <= self.bytes.len() as u64);

        // Prepare destination
        let dest = core::slice::from_raw_parts_mut(
            (segment.p_paddr + host_physical_offset.as_u64()) as *mut u8,
            segment.p_filesz as usize,
        );

        let start = segment.p_offset as usize;
        let end = (segment.p_offset + segment.p_filesz) as usize;
        dest.copy_from_slice(&self.bytes[start..end]);
    }
}

impl LoadedElf {
    /// Adds a paylog to a free location of the guest memory and returns the chosen location.
    pub fn add_payload(
        &mut self,
        data: &[u8],
        guest_allocator: &impl FrameAllocator,
    ) -> GuestPhysAddr {
        let range = guest_allocator
            .allocate_range(data.len())
            .expect("Failed to allocate guest payload");
        let host_virt_addr =
            (range.start.as_usize() + self.host_physical_offset.as_usize()) as *mut u8;
        unsafe {
            let dest = core::slice::from_raw_parts_mut(host_virt_addr, data.len());
            dest.copy_from_slice(data);
        }
        GuestPhysAddr::new(range.start.as_usize())
    }
}

//TODO(aghosn) figure out how to pass a Elf64PhdrFlags argument.
fn flags_to_prot(flags: u32) -> PtFlag {
    let mut prots = PtFlag::empty();
    if flags & Elf64PhdrFlags::PF_R.bits() == Elf64PhdrFlags::PF_R.bits() {
        prots |= PtFlag::PRESENT;
    }
    if flags & Elf64PhdrFlags::PF_W.bits() == Elf64PhdrFlags::PF_W.bits() {
        prots |= PtFlag::WRITE;
    }
    if flags & Elf64PhdrFlags::PF_X.bits() != Elf64PhdrFlags::PF_X.bits() {
        prots |= PtFlag::EXEC_DISABLE;
    }
    prots
}
