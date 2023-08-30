use core::marker::PhantomData;

use bitflags::bitflags;
use utils::HostVirtAddr;

use super::frame_allocator::FrameAllocator;
use super::walker::{Address, Level, WalkNext, Walker};

static PAGE_MASK: usize = !(0x1000 - 1);
static PAGE_OFFSET_WIDTH: usize = 12; 

pub struct PtMapper<PhysAddr, VirtAddr> {
    /// Offset between host physical memory and virtual memory.
    host_offset: usize,
    /// Offset between host physical and guest physical.
    offset: usize,
    root: PhysAddr,
    _virt: PhantomData<VirtAddr>,
}

#[cfg(not(feature = "riscv_enabled"))] 
bitflags! {
    pub struct PtFlag: u64 {
        const PRESENT = 1 << 0;
        const WRITE = 1 << 1;
        const USER = 1 << 2;
        const PAGE_WRITE_THROUGH = 1 << 3;
        const PAGE_CACHE_DISABLE = 1 << 4;
        const ACCESS = 1 << 5;
        const PSIZE = 1 << 7;
        const HALT = 1 << 11;
        const EXEC_DISABLE = 1 << 63;
    }

    pub struct PageSize: usize {
        const GIANT = 1 << 30;
        const HUGE = 1 << 21;
        const NORMAL = 1 << 12;
    }
}

#[cfg(feature = "riscv_enabled")] 
bitflags! {
    pub struct PageSize: usize {
        const GIANT = 1 << 30;
        const HUGE = 1 << 21;
        const NORMAL = 1 << 12;
    }

    pub struct PtFlag: u64 {
        const VALID = 1 << 0;
        const READ = 1 << 1;
        const WRITE = 1 << 2;
        const EXECUTE = 1 << 3;
        const USER = 1 << 4;
        const GLOBAL = 1 << 5;
        const ACCESSED = 1 << 6;
        const DIRTY = 1 << 7;
    }
}


#[cfg(feature = "riscv_enabled")] 
impl PtFlag { 
    const FLAGS_COUNT: usize = 10;

    pub const fn flags_count() -> usize {
        Self::FLAGS_COUNT
    }
}

#[cfg(not(feature = "riscv_enabled"))] 
    /// Mask to remove the top 12 bits, containing PKU keys and Exec disable bits.
pub const HIGH_BITS_MASK: u64 = !(0b111111111111 << 52);
#[cfg(not(feature = "riscv_enabled"))] 
pub const DEFAULT_PROTS: PtFlag = PtFlag::PRESENT.union(PtFlag::WRITE).union(PtFlag::USER);
pub const MAP_PAGE_TABLE: PtFlag = PtFlag::PRESENT.union(PtFlag::WRITE);

#[cfg(feature = "riscv_enabled")] 
/// Mask to remove the top 10 bits, containing N/PBMT/Reserved fields in the PTE.
pub const HIGH_BITS_MASK: u64 = !(0b1111111111 << 54);
#[cfg(feature = "riscv_enabled")] 
pub const DEFAULT_PROTS: PtFlag = PtFlag::VALID;


unsafe impl<PhysAddr, VirtAddr> Walker for PtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    type PhysAddr = PhysAddr;
    type VirtAddr = VirtAddr;

#[cfg(not(feature = "riscv_enabled"))] 
    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset + self.host_offset)
    }

#[cfg(feature = "riscv_enabled")] 
    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }
}

impl<PhysAddr, VirtAddr> PtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    pub fn new(host_offset: usize, offset: usize, root: PhysAddr) -> Self {
        Self {
            host_offset,
            offset,
            root,
            _virt: PhantomData,
        }
    }

#[cfg(not(feature = "riscv_enabled"))] 
    pub fn translate(&mut self, virt_addr: VirtAddr) -> Option<PhysAddr> {
        // Align the address
        let virt_addr = VirtAddr::from_usize(virt_addr.as_usize() & PAGE_MASK);
        let mut phys_addr = None;
        unsafe {
            self.walk(virt_addr, &mut |entry, level| {
                if *entry & PtFlag::PRESENT.bits() == 0 {
                    // Terminate the walk, no mapping exists
                    return WalkNext::Leaf;
                }
                if level == Level::L1 || *entry & PtFlag::PSIZE.bits() != 0 {
                    let raw_addr = *entry & level.mask() & HIGH_BITS_MASK;
                    let raw_addr_with_offset = raw_addr + (virt_addr.as_u64() & !level.mask());
                    phys_addr = Some(PhysAddr::from_u64(raw_addr_with_offset));
                    // We found an address, terminate the walk.
                    return WalkNext::Leaf;
                }
                // Continue to walk if not yet on a leaf
                return WalkNext::Continue;
            })
            .ok()?;
        }

        phys_addr
    }

#[cfg(feature = "riscv_enabled")] 
    pub fn translate(&mut self, virt_addr: VirtAddr) -> Option<PhysAddr> {
        // Align the address
        let virt_addr = VirtAddr::from_usize(virt_addr.as_usize() & PAGE_MASK);
        let mut phys_addr = None;
        unsafe {
            self.walk(virt_addr, &mut |entry, level| {
                if *entry & PtFlag::VALID.bits() == 0 {
                    // Terminate the walk, no mapping exists
                    return WalkNext::Leaf;
                }

                if level == Level::L1 || *entry & PtFlag::READ.bits() != 0 || *entry & PtFlag::EXECUTE.bits() != 0 {
                    let raw_addr = ((*entry & level.mask()) >> PtFlag::flags_count()) << PAGE_OFFSET_WIDTH ;
                    let raw_addr_with_offset = raw_addr + (virt_addr.as_u64() & !level.mask());
                    phys_addr = Some(PhysAddr::from_u64(raw_addr_with_offset));
                    // We found an address, terminate the walk.
                    return WalkNext::Leaf;
                }

                // Continue to walk if not yet on a leaf
                return WalkNext::Continue;
            })
            .ok()?;
        }

        phys_addr
    }

#[cfg(not(feature = "riscv_enabled"))] 
    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        log::info!("x86_map_range");

        // Align physical address first
        let phys_addr = PhysAddr::from_usize(phys_addr.as_usize() & PAGE_MASK);
        let offset = self.offset;
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    // TODO(aghosn) handle rewrite of access rights.
                    if (*entry & PtFlag::PRESENT.bits()) != 0 {
                        *entry = *entry | prot.bits();
                        *entry = *entry & !PtFlag::EXEC_DISABLE.bits();
                        return WalkNext::Continue;
                    }

                    let end = virt_addr.as_usize() + size;
                    let phys = phys_addr.as_u64() + (addr.as_u64() - virt_addr.as_u64());
                    // Opportunity to map a 1GB region
                    if level == Level::L3 {
                        if (addr.as_usize() + PageSize::GIANT.bits() <= end)
                            && (phys % (PageSize::GIANT.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    // Opportunity to map a 2MB region.
                    if level == Level::L2 {
                        if (addr.as_usize() + PageSize::HUGE.bits() <= end)
                            && (phys % (PageSize::HUGE.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(phys % (PageSize::NORMAL.bits() as u64) == 0);
                        *entry = phys | prot.bits();
                        return WalkNext::Leaf;
                    }
                    // Create an entry
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();
                    assert!(frame.phys_addr.as_u64() >= offset as u64);
                    *entry = (frame.phys_addr.as_u64() - (offset as u64)) | DEFAULT_PROTS.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }

#[cfg(feature = "riscv_enabled")]     
    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        log::info!("riscv_map_range va: {:x}, pa: {:x}", virt_addr.as_u64(), phys_addr.as_u64());
        // Align physical address first
        let phys_addr = PhysAddr::from_usize(phys_addr.as_usize() & PAGE_MASK);
        let offset = self.offset;
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    // TODO(aghosn) handle rewrite of access rights.
                   if (*entry & PtFlag::VALID.bits()) != 0 {
                        *entry = *entry | prot.bits();  //TODO(neelu): Should prot.bits() be
                                                        //checked for RWX for non-leaf entries? 
                                                        //
                        //*entry = *entry & !PtFlag::EXEC_DISABLE.bits();
                        return WalkNext::Continue;
                    }

                    let end = virt_addr.as_usize() + size;
                    log::info!("pa: {:x}, va: {:x}, addr: {:x}", phys_addr.as_u64(), addr.as_u64(), virt_addr.as_u64());
                    let phys = phys_addr.as_u64() + (addr.as_u64() - virt_addr.as_u64());
                    // Opportunity to map a 1GB region
                    if level == Level::L3 {
                        if (addr.as_usize() + PageSize::GIANT.bits() <= end)
                            && (phys % (PageSize::GIANT.bits() as u64) == 0)
                        {
                            //Make sure protection bits have either read or execute set - to
                            //denote a leaf PTE.
                            *entry = ((phys >> PAGE_OFFSET_WIDTH) << PtFlag::flags_count()) | prot.bits();
                            assert!(*entry & PtFlag::READ.bits() != 0 || *entry & PtFlag::EXECUTE.bits() != 0);
                            return WalkNext::Leaf;
                        }
                    }
                    // Opportunity to map a 2MB region.
                    if level == Level::L2 {
                        if (addr.as_usize() + PageSize::HUGE.bits() <= end)
                            && (phys % (PageSize::HUGE.bits() as u64) == 0)
                        {
                            *entry = ((phys >> PAGE_OFFSET_WIDTH) << PtFlag::flags_count()) | prot.bits();
                            assert!(*entry & PtFlag::READ.bits() != 0 || *entry & PtFlag::EXECUTE.bits() != 0);
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        log::info!("Phys: {:x}",phys);
                        assert!(phys % (PageSize::NORMAL.bits() as u64) == 0);
                        *entry = ((phys >> PAGE_OFFSET_WIDTH) << PtFlag::flags_count()) | prot.bits();
                        assert!(*entry & PtFlag::READ.bits() != 0 || *entry & PtFlag::EXECUTE.bits() != 0);
                        return WalkNext::Leaf;
                    }
                    // Create an entry
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();
                    assert!(frame.phys_addr.as_u64() >= offset as u64);
                    *entry = (frame.phys_addr.as_u64() - (offset as u64)) | DEFAULT_PROTS.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }

#[cfg(not(feature = "riscv_enabled"))] 
    /// Prints the permissions of page tables for the given range.
    pub fn debug_range(&mut self, virt_addr: VirtAddr, size: usize, dept: Level) {
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    let flags = PtFlag::from_bits_truncate(*entry);
                    let phys = *entry & ((1 << 63) - 1) & (PAGE_MASK as u64);

                    // Do not go too deep
                    match (dept, level) {
                        (Level::L4, Level::L3)
                        | (Level::L4, Level::L2)
                        | (Level::L4, Level::L1) => return WalkNext::Leaf,
                        (Level::L3, Level::L2) | (Level::L3, Level::L1) => return WalkNext::Leaf,
                        (Level::L2, Level::L1) => return WalkNext::Leaf,
                        _ => (),
                    };

                    // Print if present
                    if flags.contains(PtFlag::PRESENT) {
                        let padding = match level {
                            Level::L4 => "",
                            Level::L3 => "  ",
                            Level::L2 => "    ",
                            Level::L1 => "      ",
                        };
                        log::info!(
                            "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?}\n",
                            padding,
                            level,
                            addr.as_usize(),
                            phys,
                            flags
                        );
                        WalkNext::Continue
                    } else {
                        WalkNext::Leaf
                    }

                },
            )
            .expect("Failed to print PTs");
        }
    }

#[cfg(feature = "riscv_enabled")] 
    /// Prints the permissions of page tables for the given range.
    pub fn debug_range(&mut self, virt_addr: VirtAddr, size: usize, dept: Level) {
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    let flags = PtFlag::from_bits_truncate(*entry);
                    let phys = (*entry >> PtFlag::flags_count()) << PAGE_OFFSET_WIDTH;

                    // Do not go too deep
                    match (dept, level) {
                        (Level::L4, Level::L3)
                        | (Level::L4, Level::L2)
                        | (Level::L4, Level::L1) => return WalkNext::Leaf,
                        (Level::L3, Level::L2) | (Level::L3, Level::L1) => return WalkNext::Leaf,
                        (Level::L2, Level::L1) => return WalkNext::Leaf,
                        _ => (),
                    };

                    // Print if present
                    if flags.contains(PtFlag::VALID) {
                        let padding = match level {
                            Level::L4 => "",
                            Level::L3 => "  ",
                            Level::L2 => "    ",
                            Level::L1 => "      ",
                        };
                        log::info!(
                            "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?}\n",
                            padding,
                            level,
                            addr.as_usize(),
                            phys,
                            flags
                        );
                        WalkNext::Continue
                    } else {
                        WalkNext::Leaf
                    }
                },
            )
            .expect("Failed to print PTs");
        }
    }

}
