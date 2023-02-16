//! A Free List used for managing memory pools.

/// Free list node.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NextFree {
    /// This block is free, and the next free is at the given index.
    Free(u32),

    /// This block is not free.
    NotFree,
}

/// A typed arena, from which objects can be dynamicalle allocated and freed.
pub struct FreeList<const N: usize> {
    /// The free list, where free_list[n] returns the index of the next free object.
    free_list: [NextFree; N],

    /// The next free block, if any.
    head: u32,
}

impl<const N: usize> FreeList<N> {
    pub const fn new() -> Self {
        let mut free_list = [NextFree::NotFree; N];
        let mut i = 0;
        while i < N {
            let next = (i as u32 + 1) % (N as u32);
            free_list[i] = NextFree::Free(next);
            i += 1;
        }
        Self { free_list, head: 0 }
    }

    pub fn allocate(&mut self) -> Option<usize> {
        let head = self.head as usize;
        match self.free_list[head] {
            NextFree::Free(next) => {
                self.head = next;
                self.free_list[head] = NextFree::NotFree;
                Some(head)
            }
            NextFree::NotFree => None,
        }
    }

    pub fn free(&mut self, idx: usize) {
        // Safety check
        if self.free_list[idx] != NextFree::NotFree {
            panic!("Trying to free an already free object");
        }

        // Insert back into free list
        self.free_list[idx] = NextFree::Free(self.head);
        self.head = idx as u32;
    }
}
