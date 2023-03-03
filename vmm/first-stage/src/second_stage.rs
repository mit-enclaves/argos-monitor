//! Second-Stage

use crate::cpu;
use crate::elf::{Elf64PhdrType, ElfProgram};
use crate::guests::ManifestInfo;
use crate::mmu::frames::RangeFrameAllocator;
use crate::{println, HostPhysAddr, HostVirtAddr};
use alloc::vec::Vec;
use core::arch::asm;
use mmu::{frame_allocator::PhysRange, PtFlag, PtMapper, RangeAllocator};
use stage_two_abi::{EntryPoint, Manifest};

#[cfg(feature = "second-stage")]
const SECOND_STAGE: &'static [u8] =
    include_bytes!("../../../target/x86_64-unknown-kernel/release/second-stage");
#[cfg(not(feature = "second-stage"))]
const SECOND_STAGE: &'static [u8] = &[0; 10];

/// Size of memory allocated by the second stage.
const SECOND_STAGE_SIZE: usize = 0x1000 * 2048;
/// Virtual address to which the guest is loaded. Defined by our linker script.
const LOAD_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x80000000000);
//  Stack definitions
const STACK_VIRT_ADDR: HostVirtAddr = HostVirtAddr::new(0x90000000000);
const STACK_SIZE: usize = 0x1000 * 5;

#[derive(Clone, Copy)]
pub struct Stage2 {
    entry_point: EntryPoint,
    stack_addr: u64,
}

impl Stage2 {
    /// Hands over control to stage 2.
    pub fn jump_into(self) -> ! {
        unsafe {
            asm! {
                "mov rsp, {rsp}",      // Setupt stack pointer
                "call {entry_point}",  // Enter stage 2
                rsp = in(reg) self.stack_addr,
                entry_point = in(reg) self.entry_point,
            }
        }
        panic!("Failed entry or unexpected return from second stage");
    }
}

pub fn second_stage_allocator(stage1_allocator: &impl RangeAllocator) -> RangeFrameAllocator {
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
    info: &ManifestInfo,
    stage1_allocator: &impl RangeAllocator,
    stage2_allocator: &impl RangeAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    mailbox_addr: u64,
) -> Vec<Stage2> {
    // Read elf and allocate second stage memory
    let mut second_stage = ElfProgram::new(SECOND_STAGE);

    let elf_range = relocate_elf(&mut second_stage, stage2_allocator);
    let mut loaded_elf = second_stage
        .load::<HostPhysAddr, HostVirtAddr>(
            stage2_allocator,
            stage1_allocator.get_physical_offset(),
        )
        .expect("Failed to load second stage");

    let smp_cores = cpu::cores();
    let smp_stacks: Vec<(HostVirtAddr, HostVirtAddr, HostPhysAddr)> = (0..smp_cores)
        .map(|cpuid| {
            let stack_virt_addr = STACK_VIRT_ADDR + STACK_SIZE * cpuid;
            let (rsp, stack_phys_addr) =
                loaded_elf.add_stack(stack_virt_addr, STACK_SIZE, stage2_allocator);
            (stack_virt_addr, rsp, stack_phys_addr)
        })
        .collect();

    // If we setup I/O MMU support
    if info.iommu != 0 {
        // Map I/O MMU page, using one to one mapping
        // TODO: unmap from guest EPT
        println!("Setup I/O MMU");
        let virt_addr = HostVirtAddr::new(info.iommu as usize);
        let phys_addr = HostPhysAddr::new(info.iommu as usize);
        let size = 0x1000;
        loaded_elf.pt_mapper.map_range(
            stage2_allocator,
            virt_addr,
            phys_addr,
            size,
            PtFlag::PRESENT | PtFlag::WRITE,
        );
    }

    // If we setup VGA support
    if info.vga_info.is_valid {
        let vga_virt = HostVirtAddr::new(info.vga_info.framebuffer as usize);
        let vga_phys = pt_mapper
            .translate(vga_virt)
            .expect("Failed to translate VGA virt addr");
        println!(
            "VGA virt: 0x{:x} - phys: 0x{:x}",
            vga_virt.as_usize(),
            vga_phys.as_usize()
        );
        loaded_elf.pt_mapper.map_range(
            stage2_allocator,
            vga_virt,
            vga_phys,
            info.vga_info.len,
            PtFlag::PRESENT | PtFlag::WRITE,
        );
    }

    // Map stage 2 into stage 1 page tables
    pt_mapper.map_range(
        stage1_allocator,
        LOAD_VIRT_ADDR,
        elf_range.start,
        elf_range.size(),
        PtFlag::PRESENT | PtFlag::WRITE,
    );

    // Map the MP wakeup mailbox page into stage 2
    loaded_elf.pt_mapper.map_range(
        stage2_allocator,
        HostVirtAddr::new(mailbox_addr as usize),
        HostPhysAddr::new(mailbox_addr as usize),
        0x1000,
        PtFlag::PRESENT | PtFlag::WRITE,
    );

    loaded_elf.pt_mapper.map_range(
        stage2_allocator,
        HostVirtAddr::new(0xfee00000),
        HostPhysAddr::new(0xfee00000),
        0x1000,
        PtFlag::PRESENT | PtFlag::WRITE,
    );

    smp_stacks
        .iter()
        .for_each(|&(stack_virt_addr, _, stack_phys_addr)| {
            pt_mapper.map_range(
                stage1_allocator,
                stack_virt_addr,
                stack_phys_addr,
                STACK_SIZE,
                PtFlag::PRESENT | PtFlag::WRITE,
            );
        });

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
    manifest.info = info.guest_info.clone();
    manifest.iommu = info.iommu;
    manifest.poffset = elf_range.start.as_u64();
    manifest.voffset = LOAD_VIRT_ADDR.as_u64();
    manifest.vga = info.vga_info.clone();
    manifest.smp = smp_cores;
    manifest.mp_mailbox = mailbox_addr;

    debug::hook_stage2_offsets(manifest.poffset, manifest.voffset);
    debug::tyche_hook_stage1(1);

    // jump into second stage
    unsafe {
        // We need to manually ensure that the type corresponds to the second stage entry point
        // function.
        let entry_point: EntryPoint = core::mem::transmute(second_stage.entry.as_usize());

        smp_stacks.iter().map(|&(_, rsp, _)| {
            Stage2 {
                entry_point,
                stack_addr: rsp.as_u64(),
            }
        }).collect()
    }
}

/// Relocates the physical addresses of an elf program.
///
/// This will reserve a range of memory and tell our elf loader where to load the binary into
/// memory.
///
/// Returns the host physical range where the second stage will be loaded.
fn relocate_elf(elf: &mut ElfProgram, allocator: &impl RangeAllocator) -> PhysRange {
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
