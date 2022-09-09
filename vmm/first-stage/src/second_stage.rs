//! Second-Stage

use crate::elf::{Elf64PhdrType, ElfProgram};
use crate::mmu::frames::PhysRange;
use crate::mmu::{FrameAllocator, PtFlag, PtMapper};
use crate::{HostPhysAddr, HostVirtAddr};

#[cfg(feature = "second-stage")]
const SECOND_STAGE: &'static [u8] =
    include_bytes!("../../../target/x86_64-kernel/release/second-stage");
#[cfg(not(feature = "second-stage"))]
const SECOND_STAGE: &'static [u8] = &[0; 10];

/// Virtual address to which the guest is loaded. Defined by our linker script.
const LOAD_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x8000000);

type SecondStageEntry = extern "C" fn() -> !;

pub fn load(
    stage_allocator: &impl FrameAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    let mut second_stage = ElfProgram::new(SECOND_STAGE);

    let range = relocate_elf(&mut second_stage, stage_allocator);
    second_stage
        .load(stage_allocator, stage_allocator.get_physical_offset())
        .expect("Failed to load second stage");

    // Map stage 2 into stage 1 page tables
    let size = range.end.as_usize() - range.start.as_usize();
    pt_mapper.map_range(
        stage_allocator,
        LOAD_VIRT_ADDR,
        range.start,
        size,
        PtFlag::PRESENT | PtFlag::WRITE,
    );

    // jump into second stage
    unsafe {
        // We panic in case of unintended return, hence unreachable code after entry_point
        #![allow(unreachable_code)]

        // We need to manually ensure that the type correspond to the second stage entry point
        // function.
        let entry_point: SecondStageEntry = core::mem::transmute(second_stage.entry.as_usize());
        entry_point();
        panic!("Failed to enter second stage");
    }
}

/// Relocates the physical addresses of an elf program.
///
/// This will reserve a range of memory and tell our elf loader where to load the binary into
/// memory.
///
/// Returns the host physical range where the second stage will be loaded.
fn relocate_elf(elf: &mut ElfProgram, allocator: &impl FrameAllocator) -> PhysRange {
    let mut start = u64::MAX;
    let mut end = 0;
    for segment in &elf.segments {
        // Skip non loaded segments
        if segment.p_type != Elf64PhdrType::PT_LOAD.bits() {
            continue;
        }

        let segment_start = segment.p_paddr;
        let segment_end = segment_start + segment.p_memsz;
        if segment_start < start {
            start = segment_start;
        }
        if segment_end > end {
            end = segment_end;
        }
    }
    assert!(
        start < end,
        "The segment start must be smaller than the segment end"
    );

    // Reserve memory and compute offset
    let size = (end - start) as usize;
    let range = allocator
        .allocate_range(size)
        .expect("Failled to allocate stage 1 region");
    let offset = range.start.as_u64() as i64 - start as i64;

    // Relocate all segments
    for segment in &mut elf.segments {
        let new_padddr = (segment.p_paddr as i64 + offset) as u64;
        segment.p_paddr = new_padddr;
    }

    range
}
