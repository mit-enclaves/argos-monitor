use crate::{
    guests::elf::Elf64Phdr,
    mmu::{frames::RangeFrameAllocator, ptmapper::PtFlag, FrameAllocator, PtMapper},
    vmx,
};

use super::elf::{Elf64Hdr, Elf64PhdrFlags, Elf64PhdrType, FromBytes};
use alloc::vec::Vec;
use x86_64::align_up;

pub struct Segment {}

pub struct Section {}

pub struct ElfProgram {
    pub entry: u64,
    segments: Vec<Elf64Phdr>,
    bytes: &'static [u8],
}

impl ElfProgram {
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

        Self {
            entry: header.e_entry,
            segments: prog_headers,
            bytes: bytes,
        }
    }

    pub fn load(&self, bumper: &RangeFrameAllocator, pt_mapper: &mut PtMapper) {
        for seg in self.segments.iter() {
            unsafe {
                self.load_segment(&seg, bumper, pt_mapper);
            }
        }
    }

    unsafe fn load_segment(
        &self,
        segment: &Elf64Phdr,
        bumper: &RangeFrameAllocator,
        pt_mapper: &mut PtMapper,
    ) {
        //Strategy:
        //1. access content from the self bytes.
        //2. allocate the corresponding physical memory.
        //3. copy the content if needed.
        //4. setup the page table.
        if segment.p_type != Elf64PhdrType::PT_LOAD.bits() {
            return;
        }

        // TODO(@aghosn) might have p_paddr to handle
        if segment.p_memsz == 0 {
            return;
        }
        assert!(segment.p_align >= 0x1000);
        let dest_range = bumper
            .allocate_range(align_up(segment.p_memsz, segment.p_align))
            .expect("allocate dest");
        assert!(dest_range.end.as_u64() - dest_range.start.as_u64() >= segment.p_memsz);
        assert!(segment.p_memsz >= segment.p_filesz);
        // Copy the data.
        let virtoffset = bumper.get_physical_offset();
        let dest = core::slice::from_raw_parts_mut(
            (dest_range.start.as_u64() + virtoffset.as_u64()) as *mut u8,
            segment.p_filesz as usize,
        );
        assert!(segment.p_offset + segment.p_filesz <= self.bytes.len() as u64);
        let (start, end) = (
            segment.p_offset as usize,
            (segment.p_offset + segment.p_filesz) as usize,
        );
        dest.copy_from_slice(&self.bytes[start..end]);

        // map the page table.
        let (bstart, _) = bumper.get_boundaries();
        let prot = flags_to_prot(segment.p_flags);
        pt_mapper.map_range(
            bumper,
            vmx::GuestVirtAddr::new(segment.p_vaddr as usize),
            vmx::GuestPhysAddr::new((dest_range.start.as_u64() - bstart) as usize),
            dest_range.size(),
            prot,
        );
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
