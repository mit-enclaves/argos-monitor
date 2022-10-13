//! Typed Arenas
//!
//! Memory can be allocated dynamically for some pre-configured types. Each type gets a statically
//! allocated regions (the arena) from which objetcs can be allocated.

use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

// —————————————————————————————— Typed Arena ——————————————————————————————— //

/// A typed arena, from which objects can be dynamicalle allocated and freed.
pub struct TypedArena<T, const N: usize>
where
    T: 'static,
{
    /// The baking store from which objects are allocated.
    store: [T; N],

    /// For now we use a simple bump allocator, we will move to a better allocator later.
    bumper: usize,
}

impl<T, const N: usize> TypedArena<T, N> {
    pub const fn new(store: [T; N]) -> Self {
        Self { store, bumper: 0 }
    }

    pub fn allocate(&mut self) -> Option<Handle<T>> {
        if self.bumper >= self.store.len() {
            return None;
        }

        let handle = Handle {
            idx: self.bumper,
            _type: PhantomData,
        };
        self.bumper += 1;

        Some(handle)
    }

    #[allow(unused)]
    pub fn free(&mut self, _object: Handle<T>) {
        // TODO
    }
}

impl<T, const N: usize> Index<Handle<T>> for TypedArena<T, N> {
    type Output = T;

    fn index(&self, index: Handle<T>) -> &Self::Output {
        &self.store[index.idx]
    }
}

impl<T, const N: usize> IndexMut<Handle<T>> for TypedArena<T, N> {
    fn index_mut(&mut self, index: Handle<T>) -> &mut Self::Output {
        &mut self.store[index.idx]
    }
}

// ————————————————————————————— Object Handle —————————————————————————————— //

/// An handle to an object of type T allocated in a Typed Arena.
pub struct Handle<T> {
    idx: usize,
    _type: PhantomData<*const T>,
}

impl<T> Handle<T> {
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
