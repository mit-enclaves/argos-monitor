use blake3::Hasher;

pub const CAPACITY: usize = 2097152;
pub struct TycheHashSet {
    pub data: [Option<usize>; CAPACITY],
}

impl TycheHashSet {
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
        let mut hasher = Hasher::new();
        hasher.update(&value.to_ne_bytes());
        let binding = hasher.finalize();
        let bytes = binding.as_bytes();
        let array: [u8; 8] = bytes[0..8].try_into().unwrap();
        usize::from_ne_bytes(array) % CAPACITY
    }

    // Clears the hashset.
    pub fn clear(&mut self) {
        for i in 0..CAPACITY {
            self.data[i] = None;
        }
    }
}