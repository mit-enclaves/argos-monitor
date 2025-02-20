use const_fnv1a_hash::fnv1a_hash_64;

pub const CAPACITY: usize = 2097152;
pub struct ArgosHashSet {
    pub data: [Option<usize>; CAPACITY],
}

impl ArgosHashSet {
    /// Inserts an element into the set.
    /// Returns `true` if the element was inserted, or `false` if it already exists.
    pub fn insert(&mut self, value: usize) -> bool {
        let mut index = self.hash(value);
        for _ in 0..CAPACITY {
            match &self.data[index] {
                Some(existing) if *existing == value => return false, // Already exists
                None => {
                    self.data[index] = Some(value);
                    return true;
                }
                _ => index = (index + 1) % CAPACITY, // Linear probing
            }
        }
        panic!("HashSet is full!"); // No space left
    }

    /// Checks if an element exists in the set.
    pub fn contains(&self, value: usize) -> bool {
        let mut index = self.hash(value);
        for _ in 0..CAPACITY {
            match &self.data[index] {
                Some(existing) if *existing == value => return true,
                None => return false, // Not found
                _ => index = (index + 1) % CAPACITY,
            }
        }
        false
    }

    /// Removes an element from the set.
    /// Returns `true` if the element was removed, or `false` if it was not found.
    pub fn remove(&mut self, value: usize) -> bool {
        let mut index = self.hash(value);
        for _ in 0..CAPACITY {
            match &self.data[index] {
                Some(existing) if *existing == value => {
                    self.data[index] = None;
                    return true;
                }
                None => return false, // Not found
                _ => index = (index + 1) % CAPACITY,
            }
        }
        false
    }

    /// Hashes a value to an index within the array bounds.
    fn hash(&self, value: usize) -> usize {
        (fnv1a_hash_64(&value.to_ne_bytes(), Some(0)) as usize) % CAPACITY
    }

    // Clears the hashset.
    pub fn clear(&mut self) {
        for i in 0..CAPACITY {
            self.data[i] = None;
        }
    }
}