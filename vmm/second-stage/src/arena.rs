//! Typed Arenas
//!
//! Memory can be allocated dynamically for some pre-configured types. Each type gets a statically
//! allocated regions (the arena) from which objetcs can be allocated.

use crate::free_list::FreeList;
use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

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
    store: [T; N],

    /// The free list, where free_list[n] returns the index of the next free object.
    free_list: FreeList<N>,
}

impl<T, const N: usize> TypedArena<T, N>
where
    T: ArenaItem,
{
    pub const fn new(store: [T; N]) -> Self {
        Self {
            store,
            free_list: FreeList::new(),
        }
    }

    pub fn allocate(&mut self) -> Result<Handle<T, N>, T::Error> {
        match self.free_list.allocate() {
            Some(idx) => Ok(Handle {
                idx,
                _type: PhantomData,
            }),
            None => Err(T::ALLOCATION_ERROR),
        }
    }

    pub fn free(&mut self, object: Handle<T, N>) {
        self.free_list.free(object.idx())
    }
}

impl<T, const N: usize> Index<Handle<T, N>> for TypedArena<T, N> {
    type Output = T;

    fn index(&self, index: Handle<T, N>) -> &Self::Output {
        &self.store[index.idx]
    }
}

impl<T, const N: usize> IndexMut<Handle<T, N>> for TypedArena<T, N> {
    fn index_mut(&mut self, index: Handle<T, N>) -> &mut Self::Output {
        &mut self.store[index.idx]
    }
}

// ————————————————————————————— Object Handle —————————————————————————————— //

/// An handle to an object of type T allocated in a Typed Arena.
pub struct Handle<T, const N: usize> {
    idx: usize,
    _type: PhantomData<*const T>,
}

impl<T, const N: usize> Handle<T, N> {
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

    pub fn idx(&self) -> usize {
        self.idx
    }
}

impl<T, const N: usize> Copy for Handle<T, N> {}

impl<T, const N: usize> Clone for Handle<T, N> {
    fn clone(&self) -> Self {
        Self {
            idx: self.idx,
            _type: PhantomData,
        }
    }
}

impl<T, const N: usize> From<Handle<T, N>> for usize {
    fn from(handle: Handle<T, N>) -> Self {
        handle.idx
    }
}

impl<T, const N: usize> TryFrom<usize> for Handle<T, N>
where
    T: ArenaItem,
{
    type Error = T::Error;

    fn try_from(idx: usize) -> Result<Self, Self::Error> {
        if idx < N {
            Ok(Self::new_unchecked(idx))
        } else {
            Err(T::OUT_OF_BOUND_ERROR)
        }
    }
}
