#include "riscv48_pt.h"
#include "common.h"

/// Default profile for riscv48.
/// @warn It is incomplete.
const pt_profile_t riscv64_sv48_profile = {
  .nb_levels = RISCV48_LEVELS,
  .nb_entries = PT_NB_ENTRIES,
  .masks = {PT_LVL0_PAGE_MASK, PT_LVL1_PAGE_MASK, PT_LVL2_PAGE_MASK, PT_LVL3_PAGE_MASK},
  .shifts = {PT_LVL0_SHIFT, PT_LVL1_SHIFT, PT_LVL2_SHIFT, PT_LVL3_SHIFT},
  .how = riscv48_how_visit_leaves,
  .next = riscv48_next,
};

/// Example how function that asks to visit present leaves.
callback_action_t riscv48_how_visit_leaves(entry_t* entry, level_t level, pt_profile_t* profile)
{
  DEBUG("Entry: %lx\n", *entry);
  // Not an entry.
  if ((*entry & PT_V) != PT_V){
    DEBUG("Skipping\n");
    return SKIP; 
  }
  // Invalid entry.
  if ((*entry & PT_R) == 0 && (*entry & PT_W) != 0) {
    DEBUG("Error\n");
    return ERROR;
  }
  // Not a leaf
  if ((*entry & (PT_R | PT_W | PT_X)) == 0) {
  //if ((level == LVL1) || (level == LVL2) || (level == LVL3)) { 
    DEBUG("Walking\n");
    return WALK;
  }

  /* if (level == LVL0) {
    DEBUG("Visiting\n");
    return VISIT;
  }

  DEBUG("Error\n");
  return ERROR; */
  return VISIT;
}

/// Function visiting all the present nodes.
callback_action_t riscv48_how_visit_present(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_V) != PT_V) {
    DEBUG("Skipping\n");
    return SKIP; 
  }
  // Invalid entry.
  if ((*entry & PT_R) == 0 && (*entry & PT_W) != 0) {
    DEBUG("Error\n");
    return ERROR;
  }
  DEBUG("Visiting\n");
  return VISIT;
}

/// Example how function that asks to map missing entries.
callback_action_t riscv48_how_map(entry_t* entry, level_t level, pt_profile_t* profile)
{
  if ((*entry & PT_V) != PT_V) {
    DEBUG("Mapping\n");
    return MAP; 
  }
  // Invalid entry.
  if ((*entry & PT_R) == 0 && (*entry & PT_W) != 0) {
    DEBUG("Error\n");
    return ERROR;
  }
  DEBUG("Walking\n");
  return WALK;
}

index_t riscv48_get_index(addr_t addr, level_t level, pt_profile_t* profile)
{
  // Clear the address
  addr = addr & PT_VIRT_PAGE_MASK;
  return ((addr & profile->masks[level]) >> profile->shifts[level]);
}

entry_t riscv48_next(entry_t entry, level_t curr_level) 
{
  //return (entry & PT_PHYS_PAGE_MASK);  
      //((entry & PT_PHYS_PAGE_MASK) >> PT_FLAGS_RESERVED) << PT_PAGE_WIDTH;
    return (entry >> PT_FLAGS_RESERVED) << PT_PAGE_WIDTH; 
}
