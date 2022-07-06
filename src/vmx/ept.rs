//! Extended Page Table

use core::marker::PhantomData;

use super::bitmaps::EptEntryFlags;
use super::{Frame, FrameAllocator, GuestPhysAddr, HostPhysAddr, HostVirtAddr};

pub const GIANT_PAGE_SIZE: usize = 1 << 30;
pub const HUGE_PAGE_SIZE: usize = 1 << 21;
pub const PAGE_SIZE: usize = 1 << 12;
pub const PTE_FLAGS: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE)
    .union(EptEntryFlags::USER_EXECUTE);

// ————————————————— Host Physical to Host Virtual Mapping —————————————————— //

/// An physiscal to virtual address mapper.
///
/// This trait only serves as an alias for `Fn(usize) -> usize`, it is implemented for all closures
/// of that type.
pub trait Mapper: Clone + Fn(HostPhysAddr) -> HostVirtAddr {}
impl<T> Mapper for T where T: Clone + Fn(HostPhysAddr) -> HostVirtAddr {}

/// A mapping function, translating host physical addresses to host virtual addresses.
///
/// This is used to convert the physical addresses encountered in CPU defined structures (such as
/// page tables) to virtual addresses that can be used by the host to access those structures.
#[derive(Clone)]
pub struct HostAddressMapper<T> {
    mapping: T,
}

impl<T> HostAddressMapper<T>
where
    T: Mapper,
{
    /// Turn the given closure into an host address space mapper, than can safely be used to
    /// translate host physical addresses into host virtual addresses.
    ///
    /// SAFETY: The mapping function **must** transform any valid physical address into a
    /// corresponding valid virtual address.
    /// The mapping must be stable for the whole duration of VMX operations, that is as long as
    /// there is at least one VMX object alive. The simplest solution is to never invalidate these
    /// mapping.
    pub unsafe fn new(mapping: T) -> Self {
        Self { mapping }
    }

    /// Translate the given host physical address into a valid host virtual address.
    ///
    /// SAFETY: This function returns unbounded references, the caller is responsible to bound the
    /// references lifetime so that it doesn't outlive the object it points to.
    unsafe fn map<A>(&self, phys_addr: HostPhysAddr) -> &'static mut A {
        &mut *((self.mapping)(phys_addr).as_usize() as *mut A)
    }
}

// —————————————————————————————— Page Entries —————————————————————————————— //

/// A page table entry, generic over its level.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Entry<Level> {
    /// The raw bits
    entry: u64,
    /// A 0-sized marker
    _level: PhantomData<Level>,
}

/// A level 4 (PML4E) extended page table.
pub enum L4 {}
/// A level 3 (PDPTE) extended page table.
pub enum L3 {}
/// A level 2 (PDE) extended page table.
pub enum L2 {}
/// A level 1 (PTE) extended page table.
pub enum L1 {}

pub enum L3Ref<'a> {
    NonPresent,
    L3(&'a ExtendedPageTable<L3>),
}

pub enum L3RefMut<'a> {
    NonPresent,
    L3(&'a mut ExtendedPageTable<L3>),
}

pub enum L2Ref<'a> {
    NonPresent,
    L2(&'a ExtendedPageTable<L2>),
    GiantPage(&'a [u8; GIANT_PAGE_SIZE]),
}

pub enum L2RefMut<'a> {
    NonPresent,
    L2(&'a mut ExtendedPageTable<L2>),
    GiantPage(&'a mut [u8; GIANT_PAGE_SIZE]),
}

pub enum L1Ref<'a> {
    NonPresent,
    L1(&'a ExtendedPageTable<L1>),
    HugePage(&'a [u8; HUGE_PAGE_SIZE]),
}

pub enum L1RefMut<'a> {
    NonPresent,
    L1(&'a mut ExtendedPageTable<L1>),
    HugePage(&'a mut [u8; HUGE_PAGE_SIZE]),
}

pub enum PageRef<'a> {
    NonPresent,
    Page(&'a [u8; PAGE_SIZE]),
}

pub enum PageRefMut<'a> {
    NonPresent,
    Page(&'a mut [u8; PAGE_SIZE]),
}

impl<Level> Entry<Level> {
    /// Returns an empty (non-present) entry.
    pub const fn empty() -> Self {
        Self {
            entry: 0,
            _level: PhantomData,
        }
    }

    /// Returns true if the entry is unused (non-present).
    pub const fn is_unused(&self) -> bool {
        self.entry == 0
    }

    /// Clears the entry (mark as non-present).
    pub const fn set_unused(&mut self) {
        self.entry = 0;
    }

    /// Returns the physical address pointed by the entry.
    pub fn phys_addr(&self) -> HostPhysAddr {
        HostPhysAddr::new((self.entry & 0x000f_ffff_ffff_f000) as usize)
    }

    /// Returns the falgs of the entry.
    pub fn flags(&self) -> EptEntryFlags {
        EptEntryFlags::from_bits_truncate(self.entry)
    }

    /// Set the entry value
    pub unsafe fn set(&mut self, addr: HostPhysAddr, flags: EptEntryFlags) {
        const ADDR_MAKS: u64 = ((1 << 36) - 1) << 12;
        let addr = addr.as_u64() & ADDR_MAKS;
        self.entry = addr | flags.bits();
    }
}

impl Entry<L4> {
    pub fn deref<T: Mapper>(&self, mapping: &HostAddressMapper<T>) -> L3Ref {
        if self.is_unused() {
            L3Ref::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L3Ref::L3(mapping.map(self.phys_addr())) }
        }
    }

    pub fn deref_mut<T: Mapper>(&mut self, mapping: &HostAddressMapper<T>) -> L3RefMut {
        if self.is_unused() {
            L3RefMut::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L3RefMut::L3(mapping.map(self.phys_addr())) }
        }
    }
}

impl Entry<L3> {
    pub fn deref<T: Mapper>(&self, mapping: &HostAddressMapper<T>) -> L2Ref {
        if self.is_unused() {
            L2Ref::NonPresent
        } else if self.flags().contains(EptEntryFlags::PAGE) {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L2Ref::GiantPage(mapping.map(self.phys_addr())) }
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L2Ref::L2(mapping.map(self.phys_addr())) }
        }
    }

    pub fn deref_mut<T: Mapper>(&mut self, mapping: &HostAddressMapper<T>) -> L2RefMut {
        if self.is_unused() {
            L2RefMut::NonPresent
        } else if self.flags().contains(EptEntryFlags::PAGE) {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L2RefMut::GiantPage(mapping.map(self.phys_addr())) }
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L2RefMut::L2(mapping.map(self.phys_addr())) }
        }
    }
}

impl Entry<L2> {
    pub fn deref<T: Mapper>(&self, mapping: &HostAddressMapper<T>) -> L1Ref {
        if self.is_unused() {
            L1Ref::NonPresent
        } else if self.flags().contains(EptEntryFlags::PAGE) {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L1Ref::HugePage(mapping.map(self.phys_addr())) }
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L1Ref::L1(mapping.map(self.phys_addr())) }
        }
    }

    pub fn deref_mut<T: Mapper>(&mut self, mapping: &HostAddressMapper<T>) -> L1RefMut {
        if self.is_unused() {
            L1RefMut::NonPresent
        } else if self.flags().contains(EptEntryFlags::PAGE) {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L1RefMut::HugePage(mapping.map(self.phys_addr())) }
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L1RefMut::L1(mapping.map(self.phys_addr())) }
        }
    }
}

impl Entry<L1> {
    pub fn deref<T: Mapper>(&self, mapping: &HostAddressMapper<T>) -> PageRef {
        if self.is_unused() {
            PageRef::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { PageRef::Page(mapping.map(self.phys_addr())) }
        }
    }

    pub fn deref_mut<T: Mapper>(&mut self, mapping: &HostAddressMapper<T>) -> PageRefMut {
        if self.is_unused() {
            PageRefMut::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { PageRefMut::Page(mapping.map(self.phys_addr())) }
        }
    }

    /*pub unsafe fn set(&mut self, addr: HostPhysAddr, flags: EptEntryFlags) {
        const ADDR_MAKS: u64 = ((1 << 36) - 1) << 12;
        let addr = addr.as_u64() & ADDR_MAKS;
        self.entry = addr | flags.bits();
    }*/
}

// ——————————————————————————————— Page Table ——————————————————————————————— //

/// An Extended Page Table (EPT).
#[repr(align(0x1000))]
#[repr(C)]
pub struct ExtendedPageTable<Level> {
    /// the page entries.
    entries: [Entry<Level>; 512],
}

impl<Level> ExtendedPageTable<Level> {
    /// Clears all entries.
    #[inline]
    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.set_unused();
        }
    }

    /// Returns a reference to the entry.
    pub fn get(&self, index: usize) -> &Entry<Level> {
        &self.entries[index]
    }

    /// Returns a mutable reference to the entry.
    pub fn get_mut(&mut self, index: usize) -> &mut Entry<Level> {
        &mut self.entries[index]
    }

    /// Set an entry, returning the previous value.
    pub fn set(&mut self, entry: Entry<Level>, index: usize) -> Entry<Level> {
        core::mem::replace(&mut self.entries[index], entry)
    }
}

// ——————————————————————————— Page Table Mapper ———————————————————————————— //

pub struct ExtendedPageTableMapper<T> {
    root: EptRoot,
    translator: HostAddressMapper<T>,
}

struct EptRoot {
    root: &'static mut ExtendedPageTable<L4>,
    root_phys_addr: HostPhysAddr,
}

impl<T: Mapper> ExtendedPageTableMapper<T> {
    pub fn new(allocator: &impl FrameAllocator, translator: HostAddressMapper<T>) -> Option<Self> {
        let root_phys_addr = allocator.allocate_zeroed_frame()?.phys_addr;
        // SAFETY: the root must **never** be exposed with static lifetime outside of this
        // implementation.
        let root = unsafe { translator.map(root_phys_addr) };
        Some(Self {
            root: EptRoot {
                root,
                root_phys_addr,
            },
            translator,
        })
    }

    pub unsafe fn map(
        &mut self,
        allocator: &impl FrameAllocator,
        guest_phys: GuestPhysAddr,
        host_phys: HostPhysAddr,
        flags: EptEntryFlags,
    ) -> Result<(), ()> {
        let entry = self
            .root
            .get_l1_entry(allocator, guest_phys, PTE_FLAGS, &self.translator)?;
        entry.set(host_phys, flags);
        Ok(())
    }

    pub unsafe fn map_huge_page(
        &mut self,
        allocator: &impl FrameAllocator,
        guest_phys: GuestPhysAddr,
        host_phys: HostPhysAddr,
        flags: EptEntryFlags,
    ) -> Result<(), ()> {
        let entry = self
            .root
            .get_l2_entry(allocator, guest_phys, PTE_FLAGS, &self.translator)?;
        entry.set(host_phys, flags | EptEntryFlags::PAGE);
        Ok(())
    }

    pub unsafe fn map_giant_page(
        &mut self,
        allocator: &impl FrameAllocator,
        guest_phys: GuestPhysAddr,
        host_phys: HostPhysAddr,
        flags: EptEntryFlags,
    ) -> Result<(), ()> {
        let entry = self
            .root
            .get_l3_entry(allocator, guest_phys, PTE_FLAGS, &self.translator)?;
        entry.set(host_phys, flags | EptEntryFlags::PAGE);
        Ok(())
    }
}

impl<T> ExtendedPageTableMapper<T> {
    /// Returns the corresponding Extended Page Table Pointer (EPTP).
    ///
    /// See Intel manual volume 3 section 24.6.11.
    pub fn get_ept_pointer(&self) -> HostPhysAddr {
        let memory_kind = 6 << 0; // write-back
        let walk_length = 3 << 3; // walk length of 4

        HostPhysAddr(self.root.root_phys_addr.0 | memory_kind | walk_length)
    }

    pub fn get_l4(&mut self) -> &mut ExtendedPageTable<L4> {
        // WARNING: notice that the lifetime is bound to `self`, this is crutial for safety!
        self.root.root
    }
}

impl EptRoot {
    /// Returns the L3 entry corresponding to the 1Gb area starting at the given guest physical
    /// address.
    unsafe fn get_l3_entry<T: Mapper>(
        &mut self,
        allocator: &impl FrameAllocator,
        guest_phys: GuestPhysAddr,
        pte_flags: EptEntryFlags,
        translator: &HostAddressMapper<T>,
    ) -> Result<&mut Entry<L3>, ()> {
        let entry = self.root.get_mut(guest_phys.l4_index());
        if let L3RefMut::NonPresent = entry.deref_mut(translator) {
            let phys_addr = allocator.allocate_zeroed_frame().ok_or(())?.phys_addr;
            entry.set(phys_addr, pte_flags);
        }

        match entry.deref_mut(translator) {
            L3RefMut::L3(l3) => Ok(l3.get_mut(guest_phys.l3_index())),
            L3RefMut::NonPresent => Err(()), // Should never happen
        }
    }

    /// Returns the L2 entry corresponding to the 2Mb area starting at the given guest physical
    /// address.
    unsafe fn get_l2_entry<T: Mapper>(
        &mut self,
        allocator: &impl FrameAllocator,
        guest_phys: GuestPhysAddr,
        pte_flags: EptEntryFlags,
        translator: &HostAddressMapper<T>,
    ) -> Result<&mut Entry<L2>, ()> {
        let entry = self.get_l3_entry(allocator, guest_phys, pte_flags, translator)?;
        if let L2RefMut::NonPresent = entry.deref_mut(translator) {
            let phys_addr = allocator.allocate_zeroed_frame().ok_or(())?.phys_addr;
            entry.set(phys_addr, pte_flags);
        }

        match entry.deref_mut(translator) {
            L2RefMut::L2(l2) => Ok(l2.get_mut(guest_phys.l2_index())),
            L2RefMut::NonPresent => Err(()),
            L2RefMut::GiantPage(_) => Err(()),
        }
    }

    /// Returns the L1 entry corresponding to the 4Kb area starting at the given guest physical
    /// address.
    unsafe fn get_l1_entry<T: Mapper>(
        &mut self,
        allocator: &impl FrameAllocator,
        guest_phys: GuestPhysAddr,
        pte_flags: EptEntryFlags,
        translator: &HostAddressMapper<T>,
    ) -> Result<&mut Entry<L1>, ()> {
        let entry = self.get_l2_entry(allocator, guest_phys, pte_flags, translator)?;
        if let L1RefMut::NonPresent = entry.deref_mut(translator) {
            let phys_addr = allocator.allocate_zeroed_frame().ok_or(())?.phys_addr;
            entry.set(phys_addr, pte_flags);
        }

        match entry.deref_mut(translator) {
            L1RefMut::L1(l1) => Ok(l1.get_mut(guest_phys.l1_index())),
            L1RefMut::NonPresent => Err(()),
            L1RefMut::HugePage(_) => Err(()),
        }
    }
}

// ——————————————————————————————— EPTP List ———————————————————————————————— //

/// An EPTP list, used by the EPTP Switching VM function.
pub struct EptpList {
    frame: Frame,
}

impl EptpList {
    /// Creates a fresh EPTP List with zeroed entries.
    pub fn new(allocator: &impl FrameAllocator) -> Option<Self> {
        let frame = allocator.allocate_zeroed_frame()?;
        Some(Self { frame })
    }

    /// Returns the address of the EPTP list.
    pub fn get_ptr(&self) -> HostPhysAddr {
        self.frame.phys_addr
    }

    /// Sets an entry of the EPTP list.
    ///
    /// SAFETY: the mapping must stay alive for at least as long as the entries is used (i.e. until
    /// it is overriten or the EPTP is never used again).
    pub unsafe fn set_entry<T>(&mut self, index: usize, mapper: &ExtendedPageTableMapper<T>) {
        let eptp = mapper.get_ept_pointer();
        self.frame.as_array_page()[index] = eptp.as_u64();
    }

    /// Deletes an entry from the EPTP list.
    pub fn delete_entry(&mut self, index: usize) {
        self.frame.as_array_page()[index] = 0;
    }
}
