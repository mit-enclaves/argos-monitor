//! Typed Arenas
//!
//! Memory can be allocated dynamically for some pre-configured types. Each type gets a statically
//! allocated regions (the arena) from which objetcs can be allocated.
#![cfg_attr(not(test), no_std)]

pub mod free_list;

use core::cell::{Ref, RefCell, RefMut};
use core::marker::PhantomData;

use crate::free_list::FreeList;

// ——————————————————————————————— Item Trait ——————————————————————————————— //

pub trait ArenaItem {
    type Error;
    const OUT_OF_BOUND_ERROR: Self::Error;
    const ALLOCATION_ERROR: Self::Error;
}

// —————————————————————————————— Typed Arena ——————————————————————————————— //

/// A typed arena, from which objects can be dynamicalle allocated and freed.
pub struct TypedArena<T, const N: usize>
where
    T: 'static,
{
    /// The baking store from which objects are allocated.
    store: [RefCell<T>; N],

    /// The free list, where free_list[n] returns the index of the next free object.
    free_list: RefCell<FreeList<N>>,
}

impl<T, const N: usize> TypedArena<T, N>
where
    T: ArenaItem,
{
    pub const fn new(store: [RefCell<T>; N]) -> Self {
        Self {
            store,
            free_list: RefCell::new(FreeList::new()),
        }
    }

    pub fn allocate(&self) -> Result<Handle<T>, T::Error> {
        match self.free_list.borrow_mut().allocate() {
            Some(idx) => Ok(Handle {
                idx,
                _type: PhantomData,
            }),
            None => Err(T::ALLOCATION_ERROR),
        }
    }

    pub fn free(&self, object: Handle<T>) {
        self.free_list.borrow_mut().free(object.idx())
    }

    pub fn get(&self, handle: Handle<T>) -> Ref<T> {
        self.store[handle.idx].borrow()
    }

    pub fn get_mut(&self, handle: Handle<T>) -> RefMut<T> {
        self.store[handle.idx].borrow_mut()
    }

    pub fn is_allocated(&self, idx: usize) -> bool {
        if idx >= N {
            return false;
        }
        return !self.free_list.borrow().is_free(idx);
    }
}

// ————————————————————————————— Object Handle —————————————————————————————— //

/// An handle to an object of type T allocated in a Typed Arena.
pub struct Handle<T> {
    idx: usize,
    _type: PhantomData<*const T>,
}

impl<T> Handle<T> {
    const NULL_HANDLE: usize = usize::MAX;

    /// Creates a new chandle from raw index.
    ///
    /// Even though the index is not checked, out-of-bound indexes will only cause panic and no UB
    /// if used to access an arena.
    pub const fn new_unchecked(idx: usize) -> Self {
        Self {
            idx,
            _type: PhantomData,
        }
    }

    /// Returns a handle that will cause a panic if used.
    pub const fn null() -> Self {
        Self {
            idx: Self::NULL_HANDLE,
            _type: PhantomData,
        }
    }

    pub const fn is_null(self) -> bool {
        self.idx == Self::NULL_HANDLE
    }

    pub const fn idx(&self) -> usize {
        self.idx
    }
}

impl<T> Copy for Handle<T> {}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            idx: self.idx,
            _type: PhantomData,
        }
    }
}

impl<T> From<Handle<T>> for usize {
    fn from(handle: Handle<T>) -> Self {
        handle.idx
    }
}

impl<T> core::fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handle")
            .field("idx", &self.idx)
            .field("_type", &self._type)
            .finish()
    }
}

impl<T> core::cmp::PartialEq for Handle<T> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}

// impl<T, const N: usize> TryFrom<usize> for Handle<T, N>
// where
//     T: ArenaItem,
// {
//     type Error = T::Error;

//     fn try_from(idx: usize) -> Result<Self, Self::Error> {
//         if idx < N {
//             Ok(Self::new_unchecked(idx))
//         } else {
//             Err(T::OUT_OF_BOUND_ERROR)
//         }
//     }
// }
