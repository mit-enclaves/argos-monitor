//! Platform specific configuration

#[cfg(not(feature = "visionfive2"))]
pub fn remap_core(core: usize) -> usize {
    core
}

#[cfg(not(feature = "visionfive2"))]
pub fn remap_core_bitmap(bitmap: u64) -> u64 {
    bitmap
}

#[cfg(feature = "visionfive2")]
pub fn remap_core(core: usize) -> usize {
    (core + 1) //For linux, hart 1 is cpu 0.
}

#[cfg(feature = "visionfive2")]
pub fn remap_core_bitmap(bitmap: u64) -> u64 {
    let new_bitmap: u64 = bitmap << 1;
    new_bitmap
}
