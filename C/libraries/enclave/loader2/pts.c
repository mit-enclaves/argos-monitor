#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "pts.h"
#include "elf64.h"
#include "common.h"
#include "x86_64_pt.h"
#include "tyche_enclave.h"

uint64_t bump_nb_pages = DEFAULT_NB_PAGES; 
uint64_t bump_size = DEFAULT_BUMP_SIZE; 


static void parse_env() {
  char* nb_pages = getenv(NB_PAGES_ENVVAR);
  if (nb_pages != NULL) {
    uint64_t value = strtoull(nb_pages, NULL, 0);  
    if (value == ULLONG_MAX) {
      WARN("The provided value for NB_PAGES_ENVVAR is invalid and ignored.");
      return;
    } 
    bump_nb_pages = value;
    bump_size = bump_nb_pages * PAGE_SIZE;
  }
}


static callback_action_t default_mapper(entry_t* entry, level_t lvl, struct pt_profile_t* profile)
{
  return ERROR;
}


static entry_t* allocate(void* ptr)
{
  page_tables_t* bump =(page_tables_t*) ptr;
  if (bump == NULL) {
    ERROR("Bump is null.");
    goto failure;
  }
  if (bump->idx >= bump_nb_pages) {
    ERROR("Bump ran out of pages %d", bump->idx);
    goto failure;
  }
  page_t* page = &(bump->pages[bump->idx]);
  bump->idx++;
  return (entry_t*) page;
failure:
  return NULL;
}

static addr_t va_to_pa(addr_t addr, pt_profile_t* profile) {
  addr_t pa = 0;
  addr_t base = 0;
  info_t* info = NULL;
  if (profile == NULL) {
    ERROR("profile is null.");
    goto fail_abort;
  }
  if (profile->extras == NULL) {
    ERROR("The profile is missing extras.");
    goto fail_abort;
  } 
  info = profile->extras;
  if (info->bump == NULL) {
    ERROR("The bump is null.");
    goto fail_abort;
  }
  pa = info->bump->phys_offset;
  base = (addr_t) info->bump->pages;
  if (addr < base || addr > base + bump_size) {
    ERROR("Address is out of range.");
    goto fail_abort;
  }
  pa += (addr - base);
  return pa;
fail_abort:
   abort();
   return 0;
}

static addr_t pa_to_va(addr_t addr, pt_profile_t* profile) {
  addr_t va = 0;
  addr_t base = 0;
  info_t* info = NULL;
  if (profile == NULL) {
    ERROR("profile is null.");
    goto fail_abort;
  }
  if (profile->extras == NULL) {
    ERROR("The profile is missing extras.");
    goto fail_abort;
  } 
  info = profile->extras;
  if (info->bump == NULL) {
    ERROR("The bump is null.");
    goto fail_abort;
  }
  base = (addr_t) info->bump->pages;
  if (addr < info->bump->phys_offset) {
    ERROR("The addr is below the offset.");
    goto fail_abort;
  }
  va = addr - info->bump->phys_offset;
  if (va + base > base + bump_size) {
    ERROR("The addr is above the max address.");
    goto fail_abort;
  }
  va += base;
  return va;
fail_abort:
  abort();
  return 0;
}

addr_t align_up(addr_t addr)
{
  if (addr % PAGE_SIZE == 0) {
    return addr;
  }
  return (addr + PAGE_SIZE) & ~(PAGE_SIZE-1); 
}

int create_page_tables(uint64_t phys_offset, page_tables_t* bump, Elf64_Ehdr* header, Elf64_Phdr* segments)
{
  pt_profile_t profile;
  info_t info;
  if (bump == NULL) {
    ERROR("The provided bump variable is null.");
    goto failure;
  }

  if (header == NULL) {
    ERROR("The provided header is null.");
    goto failure;
  }

  if (segments == NULL) {
    ERROR("The provided segments is NULL");
    goto failure;
  }

  if (phys_offset % PAGE_SIZE != 0) {
    ERROR("The provided phys_offset %llx is not page aligned.", phys_offset);
    goto failure;
  }
 
  // Check if we need to change the default bump size.
  parse_env();

  // Provide the bump with memory.
  memset(&info, 0, sizeof(info_t));
  memset(&profile, 0, sizeof(pt_profile_t));
  memset(bump, 0, sizeof(page_tables_t));
  bump->phys_offset = phys_offset;
  bump->pages = mmap(NULL, bump_size, PROT_READ|PROT_WRITE,
      MAP_PRIVATE|MAP_POPULATE|MAP_ANONYMOUS, -1, 0);
  if (bump->pages == MAP_FAILED) {
    ERROR("Failed to mmap the bump pages.");
    goto failure;
  }
  // Set common parts of info
  info.bump = bump;
  info.intermed_flags = PT_PP | PT_RW | PT_ACC | PT_USR | PT_DIRT;

  // Set up the profile.
  profile = x86_64_profile;
  profile.allocate  = allocate;
  profile.pa_to_va = pa_to_va;
  profile.va_to_pa = va_to_pa;
  profile.extras = (void*) &info;
  profile.how = x86_64_how_map;

  // Set the mappers.
  profile.mappers[PT_PTE] = default_mapper;
  profile.mappers[PT_PMD] = default_mapper;
  profile.mappers[PT_PGD] = default_mapper;
  profile.mappers[PT_PML4] = default_mapper;

  // Allocate the root.
  entry_t root = (entry_t) pa_to_va((addr_t) allocate((void*)bump), &profile);

  // Map the segments.
  for (int i = 0; i < header->e_phnum; i++) {
    Elf64_Phdr seg = segments[i];
    addr_t start = seg.p_vaddr;
    addr_t end = seg.p_vaddr + align_up(seg.p_memsz);
    info.extras = (void*) &seg;
    if (pt_walk_page_range(root, PT_PML4, start, end, &profile)) {
      ERROR("Unable to map the region %llx -- %llx ", start, end);
      goto unmap_failure;
    }
  }
  return SUCCESS;
unmap_failure:
  munmap(bump->pages, bump_size);
failure:
  return FAILURE;
}
