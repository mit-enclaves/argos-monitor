//! Extended Page Table

use core::marker::PhantomData;

use super::bitmaps::EptEntryFlags;

pub const GIANT_PAGE_SIZE: usize = 1 << 30;
pub const HUGE_PAGE_SIZE: usize = 1 << 21;
pub const PAGE_SIZE: usize = 1 << 12;

/// An physiscal to virtual address mapper.
///
/// This trait only serves as an alias for `Fn(usize) -> usize`, it is implemented for all closures
/// of that type.
pub trait Mapper: Fn(usize) -> usize {}
impl<T> Mapper for T where T: Fn(usize) -> usize {}

/// A mapping function, translating host physical addresses to host virtual addresses.
///
/// This is used to convert the physical addresses encountered in CPU defined structures (such as
/// page tables) to virtual addresses that can be used by the host to access those structures.
pub struct HostAddressMapper<T>
where
    T: Mapper,
{
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
    unsafe fn map<A>(&self, phys_addr: usize) -> &'static mut A {
        &mut *((self.mapping)(phys_addr) as *mut A)
    }
}

/// The Extended Page Table Pointer (EPTP).
///
/// See Intel manual volume 3 section 24.6.11.
#[repr(transparent)]
pub struct ExtendedPageTablePointer {
    ptr: usize,
}

impl ExtendedPageTablePointer {
    pub fn as_usize(&self) -> usize {
        self.ptr
    }
}

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
    pub fn phys_addr(&self) -> usize {
        (self.entry & 0x000f_ffff_ffff_f000) as usize
    }

    /// Returns the falgs of the entry.
    pub fn flags(&self) -> EptEntryFlags {
        EptEntryFlags::from_bits_truncate(self.entry)
    }
}

impl Entry<L4> {
    pub fn deref<T: Mapper>(&self, mapping: HostAddressMapper<T>) -> L3Ref {
        if self.is_unused() {
            L3Ref::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L3Ref::L3(mapping.map(self.phys_addr())) }
        }
    }

    pub fn deref_mut<T: Mapper>(&mut self, mapping: HostAddressMapper<T>) -> L3RefMut {
        if self.is_unused() {
            L3RefMut::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { L3RefMut::L3(mapping.map(self.phys_addr())) }
        }
    }
}

impl Entry<L3> {
    pub fn deref<T: Mapper>(&self, mapping: HostAddressMapper<T>) -> L2Ref {
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

    pub fn deref_mut<T: Mapper>(&mut self, mapping: HostAddressMapper<T>) -> L2RefMut {
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
    pub fn deref<T: Mapper>(&self, mapping: HostAddressMapper<T>) -> L1Ref {
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

    pub fn deref_mut<T: Mapper>(&mut self, mapping: HostAddressMapper<T>) -> L1RefMut {
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
    pub fn deref<T: Mapper>(&self, mapping: HostAddressMapper<T>) -> PageRef {
        if self.is_unused() {
            PageRef::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { PageRef::Page(mapping.map(self.phys_addr())) }
        }
    }

    pub fn deref_mut<T: Mapper>(&mut self, mapping: HostAddressMapper<T>) -> PageRefMut {
        if self.is_unused() {
            PageRefMut::NonPresent
        } else {
            // SAFETY: the lifetime is bound to the (valid) entry.
            unsafe { PageRefMut::Page(mapping.map(self.phys_addr())) }
        }
    }
}

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
