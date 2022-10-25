//! Address representation
use core::ops::Add;

/// Mask for the last 9 bits, corresponding to the size of page table indexes.
const PAGE_TABLE_INDEX_MASK: usize = 0b111111111;

/// A macro for implementing addresses types.
///
/// An address is just a wrapper around an `usize`, with getter and setter methods.
macro_rules! addr_impl {
    ($name:ident) => {
        #[repr(transparent)]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            #[inline]
            pub const fn new(addr: usize) -> Self {
                Self(addr)
            }

            #[inline]
            pub const fn as_usize(self) -> usize {
                self.0
            }

            #[inline]
            pub const fn as_u64(self) -> u64 {
                self.0 as u64
            }

            /// Creates a virtual address that points to `0`.
            #[inline]
            pub const fn zero() -> Self {
                Self(0)
            }

            /// Aligns address downwards.
            #[inline]
            pub const fn align_down(self, align: usize) -> Self {
                assert!(align.is_power_of_two(), "`align` must be a power of two");
                let aligned = self.as_usize() & !(align - 1);
                Self::new(aligned)
            }

            /// Aligns address upwards.
            #[inline]
            pub const fn align_up(self, align: usize) -> Self {
                assert!(align.is_power_of_two(), "`align` must be a power of two");
                let align_mask = align - 1;
                let addr = self.as_usize();
                if addr & align_mask == 0 {
                    self // already aligned
                } else {
                    if let Some(aligned) = (addr | align_mask).checked_add(1) {
                        Self::new(aligned)
                    } else {
                        panic!("Attempt to add with overflow");
                    }
                }
            }

            /// Returns this address' L4 index.
            #[inline]
            pub fn l4_index(self) -> usize {
                (self.0 >> 39) & PAGE_TABLE_INDEX_MASK
            }

            /// Returns this address' L3 index.
            #[inline]
            pub fn l3_index(self) -> usize {
                (self.0 >> 30) & PAGE_TABLE_INDEX_MASK
            }

            /// Returns this address' L2 index.
            #[inline]
            pub fn l2_index(self) -> usize {
                (self.0 >> 21) & PAGE_TABLE_INDEX_MASK
            }

            /// Returns this address' L1 index.
            #[inline]
            pub fn l1_index(self) -> usize {
                (self.0 >> 12) & PAGE_TABLE_INDEX_MASK
            }
        }

        impl Add for $name {
            type Output = Self;

            fn add(self, other: Self) -> Self {
                return Self::new(self.as_usize() + other.as_usize());
            }
        }

        impl Add<usize> for $name {
            type Output = Self;
            fn add(self, other: usize) -> Self {
                return Self::new(self.as_usize() + other);
            }
        }
    };
}

addr_impl!(GuestVirtAddr);
addr_impl!(GuestPhysAddr);
addr_impl!(HostPhysAddr);
addr_impl!(HostVirtAddr);
