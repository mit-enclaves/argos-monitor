//! Second-Stage

use crate::elf::{Elf64PhdrType, ElfProgram};
use crate::mmu::frames::RangeFrameAllocator;
use crate::{HostPhysAddr, HostVirtAddr};
use core::arch::asm;
use mmu::{frame_allocator::PhysRange, FrameAllocator, PtFlag, PtMapper};
use stage_two_abi::{EntryPoint, GuestInfo, Manifest, RawStatics};

#[cfg(feature = "second-stage")]
const SECOND_STAGE: &'static [u8] =
    include_bytes!("../../../target/x86_64-kernel/release/second-stage");
#[cfg(not(feature = "second-stage"))]
const SECOND_STAGE: &'static [u8] = &[0; 10];

/// Size of memory allocated by the second stage.
const SECOND_STAGE_SIZE: usize = 0x1000 * 512;
/// Virtual address to which the guest is loaded. Defined by our linker script.
const LOAD_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x80000000000);
//  Stack definitions
const STACK_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x90000000000);
const STACK_SIZE: usize = 0x1000 * 2;

pub fn second_stage_allocator(stage1_allocator: &impl FrameAllocator) -> RangeFrameAllocator {
    let second_stage_range = stage1_allocator
        .allocate_range(SECOND_STAGE_SIZE)
        .expect("Failed to allocate second stage range");
    unsafe {
        RangeFrameAllocator::new(
            second_stage_range.start,
            second_stage_range.end,
            stage1_allocator.get_physical_offset(),
        )
    }
}

pub fn load(
    info: &GuestInfo,
    stage1_allocator: &impl FrameAllocator,
    stage2_allocator: &impl FrameAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    // Read elf and allocate second stage memory
    let mut second_stage = ElfProgram::new(SECOND_STAGE);

    let elf_range = relocate_elf(&mut second_stage, stage2_allocator);
    let mut loaded_elf = second_stage
        .load::<HostPhysAddr, HostVirtAddr>(
            stage2_allocator,
            stage1_allocator.get_physical_offset(),
        )
        .expect("Failed to load second stage");
    let (rsp, stack_phys) = loaded_elf.add_stack(STACK_VIRT_ADDR, STACK_SIZE, stage2_allocator);

    // Map stage 2 into stage 1 page tables
    pt_mapper.map_range(
        stage1_allocator,
        LOAD_VIRT_ADDR,
        elf_range.start,
        elf_range.size(),
        PtFlag::PRESENT | PtFlag::WRITE,
    );
    pt_mapper.map_range(
        stage1_allocator,
        STACK_VIRT_ADDR,
        stack_phys,
        STACK_SIZE,
        PtFlag::PRESENT | PtFlag::WRITE,
    );
    unsafe {
        // Flush TLB
        asm!(
            "mov {tmp}, cr3",
            "mov cr3, {tmp}",
            tmp = out(reg) _,
        );
    }

    // Locate and fill manifest
    let find_symbol = |symbol: &str| {
        second_stage
            .find_symbol(symbol)
            .map(|symbol| symbol.st_value as usize)
    };
    let manifest =
        unsafe { Manifest::from_symbol_finder(find_symbol).expect("Missing symbol in stage 2") };
    manifest.cr3 = loaded_elf.pt_root.as_u64();
    manifest.info = *info;
    manifest.poffset = elf_range.start.as_u64();
    manifest.voffset = LOAD_VIRT_ADDR.as_u64();

    debug::hook_stage2_offsets(manifest.poffset, manifest.voffset);
    debug::tyche_hook_stage1(1);

    // jump into second stage
    unsafe {
        // We need to manually ensure that the type correspond to the second stage entry point
        // function.
        let entry_point: EntryPoint<RawStatics> =
            core::mem::transmute(second_stage.entry.as_usize());
        call_second_stage(entry_point, manifest, rsp.as_u64());
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

unsafe fn call_second_stage(
    entry_point: EntryPoint<RawStatics>,
    manifest: &'static Manifest<RawStatics>,
    stack_addr: u64,
) -> ! {
    asm! {
        "mov rsp, {rsp}",      // Setupt stack pointer
        "call {entry_point}",  // Enter stage 2
        rsp = in(reg) stack_addr,
        entry_point = in(reg) entry_point,
        in("rdi") manifest,
    }
    panic!("Failed entry or unexpected return from second stage");
}
