#include <linux/types.h>
#include <linux/sched.h>
#include <linux/pagewalk.h>
#include <linux/mm.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <asm/pgtable_types.h>
#include "enclave.h"
#include "process.h"

#define _PAGE_VALID (_PAGE_PRESENT | _PAGE_USER)

int (*walk_page_range_prox)(struct mm_struct *mm, unsigned long start,
		unsigned long end, const struct mm_walk_ops *ops,
		void *private) = NULL;
unsigned long (*kallsyms_lookup_name_prox)(const char *name) = NULL;

/// Called when walking a range of virtual addresses for a valid page table entry.
static int pte_entry(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk) {
  struct pa_region_t* pa_region = NULL;
  uint64_t phys_addr = 0;
  struct walker_info_t* info = (struct walker_info_t*)(walk->private);

  // Safety checks.
  if (info == NULL || info->region == NULL) {
    pr_err("[TE]: Unable to retrieve info in pte_entry.\n");
    goto failure;
  }
  if (info->region->src > addr
      || (info->region->src + (info->region->end - info->region->start)) < addr) {
    pr_err("[PTE]: Start bigger than address or end less than addr.\n");
    goto failure_with_info;
  }
  if ((pte->pte & _PAGE_VALID) != _PAGE_VALID) {
    pr_err("[TE]: Missing minimal access rights for pte.\n");
    goto failure_with_info;
  }

  // Get the physical page.
  phys_addr = (uint64_t) (pte->pte & PTE_PFN_MASK);
  pa_region = kmalloc(sizeof(struct pa_region_t), GFP_KERNEL);
  if (!pa_region) {
    pr_err("[TE]: Unable to allocate new pa_region!\n");
    goto failure_with_info;
  }

  pa_region->start = phys_addr;
  pa_region->end = phys_addr + PAGE_SIZE;
  pa_region->tpe = info->region->tpe;
  dll_init_elem(pa_region, list);
  dll_init_elem(pa_region, globals);
  if (add_pa_to_region(info->region, &pa_region)) {
    pr_err("[TE]: Error adding pa_region to region\n");
    goto failure_with_malloc;
  }
  return 0;

  // Error handling.
failure_with_malloc:
  kfree(pa_region);
failure_with_info:
  info->success = 0;
failure:
  return -1;
}

static int hugetlb_entry(pte_t *pte, unsigned long hmask,
			     unsigned long addr, unsigned long next,
			     struct mm_walk *walk) {
//  struct pa_region_t* pa_region = NULL;
//  uint64_t phys_addr = 0;
//  struct walker_info_t* info = (struct walker_info_t*)(walk->private);
//  
//  // Safety checks.
//  if (info == NULL || info->region == NULL) {
//    pr_err("[TE]: Unable to retrieve info in pte_entry.\n");
//    goto failure;
//  }
//  if (info->region->start > addr || info->region->end < addr) {
//    goto failure_with_info;
//  }
//  if ((pte->pte & _PAGE_VALID) != _PAGE_VALID) {
//    pr_err("[TE]: Missing minimal access rights for pte.\n");
//    goto failure_with_info;
//  }

  //TODO implement or merge with pte entry.
  return 0;
}

static int pte_hole(unsigned long addr, unsigned long next, int depth, struct mm_walk *walk) {
  struct walker_info_t* info = (struct walker_info_t*)(walk->private);
  pr_err("[TE]: Missing PTE in the range!\n");
  info->success = 0;
  return -1;
}

static unsigned long lookup_kallsyms_lookup_name(void) {
    struct kprobe kp;
    unsigned long addr;
    
    memset(&kp, 0, sizeof(struct kprobe));
    kp.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&kp) < 0) {
        return 0;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

/// Using the kprobe trick to get a reference to the kallsyms_lookup_name func,
/// and then find the walk_page_range one.
/// Apparently this is necessary since Linux 5.77.
int init_page_walker(void) {
  kallsyms_lookup_name_prox = (void*) lookup_kallsyms_lookup_name();
  if (kallsyms_lookup_name_prox == NULL) 
  {
    pr_err("[TE]: Unable to find kallsyms_lookup_name\n");
    return -1;
  }
  walk_page_range_prox = (void*) kallsyms_lookup_name_prox("walk_page_range");
  if (walk_page_range_prox == NULL) {
    pr_err("[TE]: Unable to find walk_page_range.\n");
    return -1;
  }
  return 0;
}

/// Walks the cr3 for the given virtual region and collects the physical mappings.
/// The phys pages are added by the walker in the region->pas;
int walk_and_collect_region(struct region_t* region) {
  struct mm_walk_ops ops = {
    .pte_entry = pte_entry,
    .hugetlb_entry = hugetlb_entry,
    .pte_hole = pte_hole,
  };
  struct walker_info_t info = {region, 1};
  
  uint64_t end = region->src + (region->end - region->start);
  walk_page_range_prox(current->mm, region->src, end, &ops, &info); 
  return !(info.success);
}
