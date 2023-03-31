#include <linux/types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include "enclave.h"
#include "mapper.h"
#include "process.h"
#include "tyche_vmcall.h"
#include "../dbg/dbg.h"

#define PAGE 0x1000
// ——————————————————————— Globals to track enclaves ———————————————————————— //
static dll_list(struct enclave_t, enclaves);

static int compare_encl(tyche_encl_handle_t first, tyche_encl_handle_t second)
{
  return first == second;
}

//If end == start, we do not consider it as an overlap.
static int overlap(uint64_t s1, uint64_t e1, uint64_t s2, uint64_t e2)
{
  if ((s1 <= s2) && (s2 < e1)) {
    goto fail;
  }

  if ((s2 <= s1) && (s1 < e2)) {
    goto fail;
  }
  return 0;
fail:
  printk(KERN_NOTICE "[TE]: 1: %llx - %llx ; 2: %llx - %llx\n", s1, e1, s2, e2);
  dump_stack();
  return 1;
}

static int region_check(struct tyche_encl_add_region_t* region)
{
  if (region == NULL) {
    printk(KERN_NOTICE "[TE]: null region.\n");
    goto failure;
  }
  // Check alignment.
  if (region->start % PAGE != 0 || region->end % PAGE != 0 || region->src % PAGE != 0) {
    printk(KERN_NOTICE "[TE]: start, end or src not page aligned (%llx - %llx - %llx).\n", region->start, region->end, region->src);
    goto failure;
  }

  // Check ordering
  if (!(region->start < region->end)) {
    printk(KERN_NOTICE "[TE]: start >= end.\n");
    goto failure;
  }

  // Check access rights, we do not allow execute with write.
  if (region->flags == 0) {
    printk(KERN_NOTICE "[TE]: missing access in region.\n");
    goto failure;
  }
  if ((region->flags & MEM_WRITE) && (region->flags & MEM_EXEC)) {
    printk(KERN_NOTICE "[TE]: region is both exec and write.\n");
    goto failure;
  }

  if (region->tpe != SHARED && region->tpe != CONFIDENTIAL) {
    printk(KERN_NOTICE "[TE]: unknown region type.\n");
    goto failure;
  }

  return 1;

failure:
  return 0;
}

static struct enclave_t* find_enclave(tyche_encl_handle_t handle)
{
  struct enclave_t* encl = NULL; 
  dll_foreach((&enclaves), encl, list) {
    if (encl->handle == handle)
      break;
  }
  // We could not find the enclave.
  if (!encl) {
    pr_err("[TE]: Enclave not found.\n");
    return NULL;
  }
  // Check that the task calling is the one that created the enclave.
  if (encl->pid != current->pid) {
    printk(KERN_NOTICE "[TE]: Attempt to add a page to enclave [%llx] from a different task!\n", handle);
    printk(KERN_NOTICE " Expected: %d; got %d\n", encl->pid, current->pid);
    return NULL;
  }
  return encl;
}

void enclave_init(void)
{
  dll_init_list((&enclaves));
}

/// Add a new enclave.
/// The handle must be fresh.
int add_enclave(tyche_encl_handle_t handle, usize spawn, usize comm)
{
  struct enclave_t* encl = NULL;
  // Check whether the enclave exists.
  dll_foreach((&enclaves), encl, list) {
    if (compare_encl(encl->handle, handle)) {
      // The enclave exists.    
      return FAILURE;
    }
  }
  
  encl = kmalloc(sizeof(struct enclave_t), GFP_KERNEL);
  if (!encl) {
    // Failure to allocate.
    pr_err("[TE]: Failed to allocate new enclave!\n");
    return FAILURE;
  }

  // Setup the handle.
  encl->pid = current->pid;
  encl->handle = handle;
  dll_init_list(&encl->regions);
  dll_init_list(&encl->pts);
  dll_init_list(&encl->all_pages);
  dll_init_elem(encl, list);
  // Add to the new enclave to the list.
  dll_add((&enclaves), encl, list);

  // Invoke tyche.
  if(tyche_domain_create(encl, spawn, comm) != 0) {
    pr_err("[TE]: tyche rejected new enclave creation.\n");
    dll_remove((&enclaves), encl, list);
    return FAILURE;
  }
  printk(KERN_NOTICE "[TE]: A new enclave[%llx] was created by %d.\n", handle, current->pid); 
  return SUCCESS;
}

/// Deletes all the physical regions in a region.
static void delete_region_pas(struct region_t* region)
{
  struct pa_region_t* curr = NULL;
  for (curr = region->pas.head; curr != NULL;) {
    struct pa_region_t* tmp = curr->list.next;
    kfree(curr);
    curr = tmp;
  }
}

/// Add a region to an existing enclave.
int add_region(struct tyche_encl_add_region_t* region)
{
  struct enclave_t* encl = NULL; 
  struct region_t* prev = NULL;
  struct region_t* e_reg = NULL;
  struct region_t* reg_iter = NULL;
  
  // Find the enclave.
  encl = find_enclave(region->handle);
  if (encl == NULL) {
    pr_err("[TE]: unable to find enclave in add_region.\n");
    return FAILURE;
  }
 
  // Lightweight checks.
  // Mappings to physical memory are checked later.
  if (!region_check(region))
  {
    pr_err("[TE]: Malformed region.\n");
    return FAILURE;
  }

  // Allocate the region & set its attributes.
  e_reg = kmalloc(sizeof(struct region_t), GFP_KERNEL);
  if (!e_reg) {
    pr_err("[TE]: Failed to allocate a new region.\n");
    return FAILURE;
  }
  e_reg->start = region->start;
  e_reg->end = region->end;
  e_reg->src = region->src;
  e_reg->flags = region->flags;
  e_reg->tpe = region->tpe;
  dll_init_list(&e_reg->pas);
  dll_init_elem(e_reg, list); 

  // Check there is no overlap with other regions.
  // We keep the list sorted and attempt to merge regions whenever possible. 
  for (reg_iter = encl->regions.head; reg_iter != NULL;) {
    if (overlap(reg_iter->start, reg_iter->end, e_reg->start, e_reg->end)) {
      pr_err("[TE]: Virtual address overlap detected.\n");
      dump_stack();
      goto failure;
    } 

    // CASES WHERE: e_reg is on the left.

    // Too far in the list already and no merge.
    if (reg_iter->start > e_reg->end 
        || (reg_iter->start == e_reg->end && 
          (reg_iter->tpe != e_reg->tpe || reg_iter->flags != e_reg->flags))) {
      //TODO is that correct?
      //prev = reg_iter;
      break;
    }
    
    // Contiguous, we merge only if the src is also contiguous.
    // The second part of the && is redundant but makes code more readable.
    if( reg_iter->start == e_reg->end
        && reg_iter->src == (e_reg->src + (e_reg->end - e_reg->start)) 
        && reg_iter->tpe == e_reg->tpe 
        && reg_iter->flags == e_reg->flags) {
      reg_iter->start = e_reg->start;
      reg_iter->src = e_reg->src;
      kfree(e_reg);
      e_reg = NULL;
      prev = NULL;
      break;
    }

    // CASES WHERE: e_reg is on the right.
   
    // Safely skip this entry.
    if (reg_iter->end < e_reg->start ||
      (reg_iter->end == e_reg->start 
       && (reg_iter->tpe != e_reg->tpe || reg_iter->flags != e_reg->flags))) {
      goto next;
    }

    // We need to merge and have no guarantee that the next region does not
    // overlap.
    // Once again, the tpe check is redundant and is for readabilitty.
    if (reg_iter->end == e_reg->start 
        && e_reg->src == (reg_iter->src + (reg_iter->end - reg_iter->start)) 
        && reg_iter->tpe == e_reg->tpe
        && reg_iter->flags == e_reg->flags) {
      struct region_t* next = reg_iter->list.next;
      // There is an overlap with the next element.
      // We cannot add the region to the list.
      if (next != NULL && overlap(reg_iter->start, e_reg->end, next->start, next->end)){
        goto failure;
      }
      // Merge and remove.
      e_reg->start = reg_iter->start;
      dll_remove(&(encl->regions), reg_iter, list); 
      kfree(reg_iter);
      reg_iter = prev;
      if (prev != NULL) {
        prev = prev->list.prev;
      } else {
        prev = NULL;
        reg_iter = encl->regions.head;
      }
      continue;
    }
next:
    prev = reg_iter;
    reg_iter = reg_iter->list.next;
  }

  // The region has been merged.
  if (e_reg == NULL) {
    goto done;
  }

  if (prev != NULL) {
    dll_add_after(&encl->regions, e_reg, list, prev);
  } else {
    dll_add_first(&encl->regions, e_reg, list);
  }
done:
  return SUCCESS;
failure:
  kfree(e_reg);
  pr_err("[TE]: add_region failure.\n");
  return FAILURE;
}

int add_stack_region(struct tyche_encl_add_region_t* region)
{
  struct enclave_t* encl = NULL; 
  if (add_region(region) != 0) {
    return FAILURE;
  }
  encl = find_enclave(region->handle);
  if (encl == NULL) {
    pr_err("[TE]: unable to find the enclave.\n");
    return FAILURE;
  }
  encl->stack = region->end;
  return SUCCESS;
}

/// Done adding virtual regions to an enclave.
/// Commit the regions and find the corresponding physical pages.
/// @warn: Not the most efficient implementation, we go through the list
/// several times. We could merge all of this within the loop.
/// For now, keep it this way to ease debugging and readability.
int commit_enclave(struct tyche_encl_commit_t* commit)
{
  void * ptr = NULL;
  struct enclave_t* encl = NULL; 
  struct region_t* region = NULL;
  struct pa_region_t* pa_region = NULL;
  if (commit == NULL) {
    pr_err("[TE]: Null commit message.\n");
    return FAILURE;
  }
  encl = find_enclave(commit->handle);
  if (encl == NULL || current == NULL) {
    pr_err("[TE]: unable to find enclave in commit_enclave.\n");
    return FAILURE;
  }

  if (encl->pid != current->pid) {
    pr_err("[TE]: The enclave cannot be commited by another pid.\n");
    return FAILURE;
  }
  
  dll_foreach(&(encl->regions), region, list) {
    // Collect the physical pages.
    if (walk_and_collect_region(region) != 0) {
      pr_err("[TE]: failure in walk_and_collect!\n");
      goto failure; 
    }
  }

  // Create the cr3.
  if (build_enclave_cr3(encl)) {
    pr_err("[TE]: failed to build enclave cr3.\n");
    goto failure;
  }
  //TODO this was for debugging cr3
  /*register_cr3(encl->cr3);
  debugging_cr3();*/

  // All pages should be inside all_pages now.
  // Call tyche to split regions. 
  pa_region = NULL;
  dll_foreach(&(encl->all_pages), pa_region, globals) {
    // The call will set the handle in the pa_region.
    if (tyche_share_grant(encl, pa_region) != 0) {
      pr_err("[TE]: tyche_share_grant failed %d.\n", pa_region->tpe);
      goto failure;
    }
  }

  // Set the stack and entry.
  encl->stack = commit->stack;
  encl->entry = commit->entry;

  // Now seal the enclave. 
  if (tyche_seal_enclave(encl) != 0) {
    pr_err("[TE]: tyche_seal_enclave failed.\n");
    goto failure;
  }

  // Give back the handle for the domain.
  commit->domain_handle = encl->tyche_handle;
  return SUCCESS;

failure:
  // Delete all the pas.
  region = NULL;
  dll_foreach(&(encl->regions), region, list) {
    delete_region_pas(region);
  }
  // Delete the enclave page tables.
  for (pa_region = encl->pts.head; pa_region != NULL; ) {
    struct pa_region_t* tmp = pa_region;
    pa_region = pa_region->list.next;
    dll_remove(&(encl->pts), tmp, list);
    ptr = phys_to_virt((phys_addr_t)(tmp->start)); 
    free_pages_exact(ptr, 0x1000);
    kfree(tmp);
  }
  encl->cr3 = 0;
  pr_info("[TE]: deleted the enclave pages.\n");
  return FAILURE;
}

/// Adds a physical range to an enclave region.
/// It is important that this function does not change the order in which 
/// physical regions are added as this should correspond to the order in which
/// we walk through them to build the new cr3 later on.
/// There is absolutely no merging here.
int add_pa_to_region(struct region_t* region, struct pa_region_t** pa_region) {
  struct pa_region_t* curr = NULL;
  dll_init_elem(*pa_region, list);
  
  // Easy case, the list is empty.
  if (dll_is_empty(&region->pas)) {
    dll_add(&region->pas, *pa_region, list); 
    return 0;
  }

  // Check there is no overlap. 
  dll_foreach(&(region->pas), curr, list) {
    // Safety check first.
    if (overlap(curr->start, curr->end, (*pa_region)->start, (*pa_region)->end)) {
      return -1;
    }
  }
  // All good, we add at the tail of the list.
  dll_add(&region->pas, *pa_region, list);
  return SUCCESS;
}

int delete_enclave(tyche_encl_handle_t handle)
{
  struct enclave_t* encl = NULL; 
  struct pa_region_t* pa_reg = NULL;
  struct region_t* reg = NULL;
  // Find the enclave.
  encl = find_enclave(handle);
  if (encl == NULL) {
    pr_err("[TE] delete_enclave unable to find enclave.\n");
    return FAILURE;
  }
  // Collect all the handles and re-merge.
  dll_foreach(&(encl->all_pages), pa_reg, globals) {
    if (tyche_revoke_region(encl->tyche_handle, pa_reg->start, pa_reg->end) != SUCCESS) {
      pr_err("[TE] failed to revoke a region.\n");
      return FAILURE;
    }
  }

  // Delete all the pas in all_pages.
  while(!dll_is_empty(&(encl->all_pages))) {
    struct pa_region_t* head = encl->all_pages.head;
    dll_remove(&(encl->all_pages), head, globals);
    kfree(head);
  }
  // Delete all the pas in regions.
  dll_foreach(&(encl->regions), reg, list) {
    while(!dll_is_empty(&(reg->pas))) {
      struct pa_region_t* head = reg->pas.head;
      dll_remove(&(reg->pas), head, list);
      kfree(head);
    }
  }
  // Delete all the regions.
  while(!dll_is_empty(&(encl->regions))) {
    struct region_t* head = encl->regions.head;
    dll_remove(&(encl->regions), head, list);
    kfree(head);
  }

  // Remove the enclave from the list.
  dll_remove(&(enclaves), encl, list);

  // Delete the tyche domain.
  if (tyche_revoke_domain(encl->tyche_handle) != SUCCESS) {
    pr_err("[TE] unable to delete enclave\n");
    return FAILURE;
  } 
  kfree(encl);
  return SUCCESS;
}

int switch_enclave(struct tyche_encl_switch_t* sw)
{
  struct enclave_t* encl = NULL;
  encl = find_enclave(sw->handle);
  if (encl == NULL) {
    pr_err("[TE] unable to find enclave for switch.\n");
    return FAILURE;
  }
  //TODO might need a CLI?
  return tyche_switch_domain(encl->tyche_handle, sw->args);
}

// —————————————————————————————— Internal API —————————————————————————————— //
int add_merge_global(struct enclave_t* enclave, struct pa_region_t* region)
{
  struct pa_region_t* iter = NULL;
  struct pa_region_t* prev = NULL;
  if (enclave == NULL || region == NULL) {
    return -1;
  }
  for(iter = enclave->all_pages.head; iter != NULL;) {
    if (overlap(iter->start, iter->end, region->start, region->end)) {
      pr_err("[TE]: physical region address overlap detected.\n");
      goto failure;
    }

    // CASES WHERE: region is on the left.

    // Too far in the list already and no merge.
    if (iter->start > region->end
        || (iter->start == region->end && iter->tpe != region->tpe)) {
      break;
    }

    // Contiguous, we merge on if the types are the same.
    if (iter->start == region->end && iter->tpe == region->tpe) {
      iter->start = region->start;
      kfree(region);
      region = NULL;
      prev = NULL;
      break;
    }

    // CASES WHERE: region is on the right.
    
    // Safely skip this entry.
    if (iter->end < region->start
        || (iter->end == region->start && iter->tpe != region->tpe)) {
      goto next;
    }

    // We need to merge and have no guarantee the next region does not 
    // overlap.
    if (iter->end == region->start && iter->tpe == region->tpe) {
      struct pa_region_t* next = iter->globals.next;
      // There is an overlap with the next element.
      // We cannot add the region to the list.
      if (next != NULL && overlap(iter->start, region->end, next->start, next->end)) {
        goto failure;
      }
      // Merge and remove.
      region->start = iter->start;
      dll_remove(&(enclave->all_pages), iter, globals);
      kfree(iter);
      iter = prev;
      if (prev != NULL) {
        prev = prev->globals.prev;
      } else {
        prev = NULL;
        iter = enclave->all_pages.head;
      }
      continue;
    }
next:
    prev = iter;
    iter = iter->globals.next;
  }
  // The region has been merge on the left.
  if (region == NULL) {
    goto done; 
  }

  if (prev != NULL) {
    dll_add_after(&(enclave->all_pages), region, globals, prev);
  } else {
    dll_add_first(&(enclave->all_pages), region, globals);
  }
done:
  return 0;
failure:
  return -1;
}
