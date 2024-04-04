//! Platform specific configuration

#[cfg(not(feature = "bare_metal"))]
pub fn remap_core(core: usize) -> usize {
    core
}

#[cfg(not(feature = "bare_metal"))]
pub fn remap_core_bitmap(bitmap: u64) -> u64 {
    bitmap
}

#[cfg(feature = "bare_metal")]
pub fn remap_core(core: usize) -> usize {
    // Our harware has hyper-threads, and renames all co-located threads
    if core < 8 {
        core * 2
    } else {
        (core - 8) * 2 + 1
    }
}

#[cfg(feature = "bare_metal")]
pub fn remap_core_bitmap(bitmap: u64) -> u64 {
    let mut new_bitmap = 0;
    for idx in 0..16 {
        if bitmap & (1 << idx) != 0 {
            new_bitmap |= 1 << remap_core(idx);
        }
    }

    new_bitmap
}
