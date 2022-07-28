use alloc::vec::Vec;

use super::elf::{Elf64Hdr, Elf64Phdr, Elf64PhdrFlags, Elf64PhdrType, FromBytes};
use crate::mmu::frames::{PhysRange, RangeFrameAllocator};
use crate::mmu::{FrameAllocator, PtFlag, PtMapper};
use crate::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};

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
    segments: Vec<Elf64Phdr>,
    bytes: &'static [u8],
    mapping: ElfMapping,
    stack: Option<(GuestVirtAddr, usize)>,
    payload: Option<Vec<u8>>,
}

pub struct LoadResult {
    pub pt_root: GuestPhysAddr,
    pub payload: Option<GuestPhysAddr>,
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
        let entry = entry.expect("Couldn't fiend guest entry point");

        Self {
            entry: GuestVirtAddr::new(entry as usize),
            phys_entry: GuestPhysAddr::new(phys_entry as usize),
            segments: prog_headers,
            mapping: ElfMapping::ElfDefault,
            stack: None,
            payload: None,
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

    /// Specifies a payload to copy to the guest memory.
    pub fn add_payload(&mut self, payload: Vec<u8>) {
        self.payload = Some(payload);
    }

    /// Loads the guest program and setup the page table inside the guest memory.
    ///
    /// On success, returns the guest physical address of the guest page table root (to bet set as
    /// CR3).
    pub fn load(
        &self,
        guest_memory: PhysRange,
        host_physical_offset: HostVirtAddr,
    ) -> Result<LoadResult, ()> {
        // Compute the highest physical address used by the guest.
        // The remaining space can be used to allocate page tables.
        let mut highest_addr = 0;
        for seg in self.segments.iter() {
            if seg.p_type != Elf64PhdrType::PT_LOAD.bits() {
                continue;
            }
            highest_addr = core::cmp::max(highest_addr, seg.p_paddr + seg.p_memsz);
        }

        // Choose where to place PT in guest physical and virtual memory
        let guest_pt_offset = 0xe0000000; // Pick an arbitrary offset for now
        let guest_pt_size = 0x1000 * 1000; // enough space for 1000 guest PT
        let guest_phys_pt_start = highest_addr;
        let guest_phys_pt_end = guest_phys_pt_start + guest_pt_size;
        let guest_virt_pt_start = highest_addr + guest_pt_offset;
        let guest_virt_pt_end = guest_virt_pt_start + guest_pt_size;

        // Check for collisions between PT and other elf segments in guest virtual address space
        // TODO: handle identity mapping (i.e. check phys addr instead of virt addr).
        for seg in self.segments.iter() {
            let seg_start = seg.p_vaddr;
            let seg_end = seg_start + seg.p_memsz;
            if seg_end >= guest_virt_pt_start && seg_start <= guest_virt_pt_end {
                return Err(()); // Collision between PT and elf segment!
            }
        }

        // Allocates page tables within the guest
        let guest_allocator = unsafe {
            RangeFrameAllocator::new(
                HostPhysAddr::new((guest_phys_pt_start + guest_memory.start.as_u64()) as usize),
                HostPhysAddr::new((guest_phys_pt_end + guest_memory.start.as_u64()) as usize),
                host_physical_offset,
            )
        };
        let pt_root = guest_allocator.allocate_frame().ok_or(())?.zeroed();
        let pt_root_guest_phys_addr =
            GuestPhysAddr::new((pt_root.phys_addr.as_u64() - guest_memory.start.as_u64()) as usize);
        let mut pt_mapper = PtMapper::new(
            host_physical_offset.as_u64() as usize,
            guest_memory.start.as_u64() as usize,
            pt_root_guest_phys_addr,
        );
        let mut result = LoadResult {
            pt_root: pt_root_guest_phys_addr,
            payload: None,
        };

        // Load and map segments
        for seg in self.segments.iter() {
            if seg.p_type != Elf64PhdrType::PT_LOAD.bits() {
                // Skip non-load segments.
                continue;
            }
            unsafe {
                self.load_segment(&seg, &guest_memory, host_physical_offset);
                self.map_segment(seg, &mut pt_mapper, &guest_allocator);
            }
        }

        // Create stack, if required
        if let Some((stack_address, size)) = self.stack {
            // TODO: properly choose a valid stack physical address. Zero is not ideal...
            let stack_prot = PtFlag::WRITE | PtFlag::PRESENT | PtFlag::EXEC_DISABLE | PtFlag::USER;
            pt_mapper.map_range(
                &guest_allocator,
                stack_address,
                GuestPhysAddr::new(0),
                size,
                stack_prot,
            );
        }
        // Copy payload into guest memory, if any
        if let Some(payload) = &self.payload {
            let range = guest_allocator
                .allocate_range(payload.len())
                .expect("Failed to allocate guest payload");
            let host_virt_addr =
                (range.start.as_usize() + host_physical_offset.as_usize()) as *mut u8;
            unsafe {
                let dest = core::slice::from_raw_parts_mut(host_virt_addr, payload.len());
                dest.copy_from_slice(payload);
            }
            result.payload = Some(GuestPhysAddr::new(
                range.start.as_usize() - guest_memory.start.as_usize(),
            ));
        }

        Ok(result)
    }

    /// Maps an elf segment at the desired virtual address.
    unsafe fn map_segment(
        &self,
        segment: &Elf64Phdr,
        mapper: &mut PtMapper,
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
    unsafe fn load_segment(
        &self,
        segment: &Elf64Phdr,
        guest_memory: &PhysRange,
        host_physical_offset: HostVirtAddr,
    ) {
        // Sanity checks
        assert!(segment.p_align >= 0x1000);
        assert!(segment.p_memsz >= segment.p_filesz);
        assert!(segment.p_offset + segment.p_filesz <= self.bytes.len() as u64);
        assert!(
            segment.p_paddr + segment.p_memsz
                <= guest_memory.end.as_u64() - guest_memory.start.as_u64(),
            "Not enought guest memory"
        );

        // Prepare destination
        let dest = core::slice::from_raw_parts_mut(
            (guest_memory.start.as_u64() + segment.p_paddr + host_physical_offset.as_u64())
                as *mut u8,
            segment.p_filesz as usize,
        );

        let start = segment.p_offset as usize;
        let end = (segment.p_offset + segment.p_filesz) as usize;
        dest.copy_from_slice(&self.bytes[start..end]);
    }
}

//TODO(aghosn) figure out how to pass a Elf64PhdrFlags argument.
fn flags_to_prot(flags: u32) -> PtFlag {
    let mut prots = PtFlag::EMPTY;
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
