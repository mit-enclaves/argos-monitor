#include "tyche_capabilities.h"
#include "tyche_api.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
domain_t local_domain;

static int access_is_less(unsigned long a1, unsigned long a2)
{
  if ((a1 & CAPA_READ) != 0 && (a2 & CAPA_READ) == 0) {
    return 0;
  }
  if ((a1 & CAPA_WRITE) != 0 && (a2 & CAPA_WRITE) == 0) {
    return 0;
  }
  if ((a1 & CAPA_EXEC) != 0 && (a2 & CAPA_EXEC) == 0) {
    return 0;
  }
  return 1;
}

// —————————————————————————————— Public APIs ——————————————————————————————— //
int init_domain(capa_alloc_t allocator, capa_dealloc_t deallocator, capa_dbg_print_t print)
{
  capa_index_t i = 0;
  capa_index_t nb_capa = 0;
  if (allocator == 0 || deallocator == 0 || print == 0) {
    return -1;
  }
  local_domain.alloc = allocator;
  local_domain.dealloc = deallocator;
  local_domain.print = print;
  dll_init_list(&(local_domain.capabilities));

  // Acquire the current domain's id.
  if (tyche_get_domain_id(&(local_domain.id)) != 0) {
    local_domain.print("unable to get the domain id.\n");
    goto fail;
  }
  
  // Read the number of ECS entries.
  if (ecs_read_size(&nb_capa) != 0) {
    goto fail;
  }

  // Enumerate the regions for this domain.
  for (i = TYCHE_ECS_FIRST_ENTRY; i < nb_capa; i++) {
    capability_t* capa = (capability_t*) local_domain.alloc(sizeof(capability_t));
    if (capa == NULL) {
      local_domain.print("unable to allocate capa.\n");
      goto failure;
    }
    if (ecs_read_entry(i, &(capa->handle)) != 0) {
      local_domain.print("unable to read ecs.\n");
      goto failure;
    }
    dll_init_elem(capa, list); 
    // Get the handle details.
    if (tyche_read_capa(capa) != 0) {
      local_domain.print("unable to read the capa.\n");
      goto failure;
    }
    // For the moment we do not support bootstrapping a domain with revok handles.
    if ((capa->access & CAPA_REVOK) != 0) {
      local_domain.print("init_domain found a revocation handle.\n");
      goto failure;
    }
    //TODO we need to figure this out too.
    capa->status = ActiveCapa;
    if (capa->is_shared != 0) {
      local_domain.print("There is a handle that is already shared?");
    }

    // Add the capability to the list.
    dll_add(&(local_domain.capabilities), capa, list);
  }
  // We are all done
  return 0;
failure:
  while(!dll_is_empty(&local_domain.capabilities)) {
    capability_t* capa = local_domain.capabilities.head;
    dll_remove(&(local_domain.capabilities), capa, list);
    local_domain.dealloc((void*)capa);
  }
fail:
  local_domain.print("failure to init domain.\n");
  return -1;
}

int create_domain(domain_id_t* handle)
{
  if (handle == NULL) {
    goto fail;
  }
  if (tyche_create_domain(handle) != 0) {
    goto fail;
  }
  return 0;
fail:
  return -1;
}

capability_t* split_capa(capability_t* capa, paddr_t split_addr)
{
  capability_t *split = NULL;
  if (capa == NULL) {
    local_domain.print("capa null.\n");
    goto failure;
  }
  // Wrong type.
  if ((capa->access & CAPA_REVOK) != 0) {
    local_domain.print("trying to split a revok capa.");
    goto failure;
  }
  if (capa->is_owned == 0 || capa->is_shared != 0) {
    local_domain.print("trying to split a capa that either not owned or is shared.");
    goto failure;
  }
  // Wrong capability.
  if (!dll_contains(capa->start, capa->end, split_addr)) {
    local_domain.print("wrong capability, does not contain.\n");
    goto failure;
  }

  // Allocate the new capability.
  split = (capability_t*) local_domain.alloc(sizeof(capability_t));
  if (split == NULL) {
    local_domain.print("split alloc failed.\n");
    goto failure;
  }
  split->start = split_addr;
  split->end = capa->end;
  split->is_owned = capa->is_owned;
  split->is_shared = capa->is_shared;
  split->status = capa->status;
  split->access = capa->access;
  dll_init_elem(split, list);
  dll_init_list(&(split->revoks));

  // Call tyche for the split.
  if (tyche_split_capa(capa->handle, split_addr, &(split->handle)) != 0) {
    local_domain.print("tyche rejected the split.\n");
    goto fail_dealloc;
  }
  
  // We managed to split!
  capa->end = split_addr;
  dll_add(&(local_domain.capabilities), split, list);
  return split;
fail_dealloc:
  local_domain.dealloc((void*)split);
failure:
  return NULL;
}

int transfer_capa(domain_id_t dom, paddr_t start, paddr_t end, capability_type_t tpe)
{
  // 1. Find the capa.
  // 2. Split.
  // 3. If tpe == Confidential -> remove
  // 4. call the transfer.
  capability_t* curr = NULL;
  capability_t* split = NULL;
  unsigned long access = 0;
  // Quick checks.
  if (start >= end || tpe > MaxTpe || tpe < MinTpe 
      || ((start % ALIGNMENT) != 0) || ((end % ALIGNMENT) != 0)) {
    goto failure;
  }
  dll_foreach(&(local_domain.capabilities), curr, list) {
    if (curr->start == start && curr->end == end) {
      // Perfect match.
      break;
    }
    if (dll_contains(curr->start, curr->end, start)
        && dll_contains(curr->start, curr->end, end)) {
      // We found the region.
      break;
    }
  }

  // Unable to find the capa.
  if (curr == NULL) {
    local_domain.print("failed to find capa in transfer.\n");
    goto failure;
  }

  // We cannot grant something confidential if it is not confidential.
  access = translate_access(tpe);
  if (!access_is_less(access, curr->access)) {
    local_domain.print("attempt to increase access rights in transfer.\n");
    goto failure;
  }
  if (tpe >= SharedRO && tpe <= Shared && curr->status == PausedCapa) {
    // Impossible to share the capa if it is paused (i.e., part of a grant).
    local_domain.print("attempt to share a granted region.\n");
    goto failure;
  }
  if (tpe >= ConfidentialRO && tpe <= Confidential && curr->status != ActiveCapa) {
      // Impossible to do a grant if the region is not exclusively owned.
      local_domain.print("attempt to grant a region that's not exclusively owned.\n");
      goto failure;
  } 
  
  // Split the capability.
  split = curr;
  if (curr->start != start || curr->end != end) {
    split = split_capa(curr, start);
    if (split == NULL) {
      local_domain.print("split failed in transfer.\n");
      goto failure;
    }

    // Do we need a three way split?
    if (split->end > end) {
      if (split_capa(split, end) == NULL) {
        local_domain.print("second split failed.\n");
        goto failure;
      }
    }
  }

  // Now transfer with the right tpe.
  if (tpe >= ConfidentialRO && tpe <= Confidential) {
    revok_handle_t* revok = (revok_handle_t*) local_domain.alloc(sizeof(revok_handle_t)); 
    if (revok == NULL) {
      goto failure;
    }
    split->status = PausedCapa;
    dll_init_elem(revok, list);
    revok->domain = dom;
    if(tyche_grant_capa(dom, split->handle, tpe, &(revok->revok_handle)) != 0) {
      local_domain.print("Failure to grant capa.\n");
      split->status = ActiveCapa;
      local_domain.dealloc(revok);
      goto failure;
    }
    dll_add(&(split->revoks), revok, list);
  } else {
    revok_handle_t* revok = NULL;
    capa_status_t prev = split->status;
    // First check there isn't already a shared handle for this region.
    dll_foreach(&(split->revoks), revok, list) {
      if (revok->domain == dom) {
        local_domain.print("The region is already shared with the domain.\n");
        goto failure;
      } 
    }
    revok = (revok_handle_t*) local_domain.alloc(sizeof(revok_handle_t));
    if (revok == NULL) {
      goto failure;
    }
    split->status = SharedCapa;
    revok->domain = dom;
    dll_init_elem(revok, list);
    if (tyche_share_capa(dom, split->handle, tpe, &(revok->revok_handle)) != 0) {
      local_domain.print("Failure to grant capa.\n");
      split->status = prev;
      local_domain.dealloc(revok);
      goto failure;
    }
    dll_add(&(split->revoks), revok, list); 
  }
  return 0;
failure:
  local_domain.print("failure in transfer.\n");
  return -1;
}

int seal_domain(domain_id_t handle, paddr_t cr3, paddr_t entry, paddr_t stack, capa_index_t* invoke_capa)
{
  local_domain.print("About to seal a domain.\n");
  return tyche_domain_seal(handle, cr3, entry, stack, invoke_capa);
}

int revoke_capa(domain_id_t id, paddr_t start, paddr_t end)
{
  capability_t* curr = NULL;
  capability_t* prev = NULL;
  capability_t* next = NULL;
  // Quick checks
  if (start >= end) {
    local_domain.print("revoke capa start greater or equal to end");
    goto failure;
  }
  dll_foreach(&(local_domain.capabilities), curr, list) {
    if (curr->start == start && curr->end == end) {
      // we found the correct capa.
      break;
    }
  }
  if (curr == NULL) {
    local_domain.print("revoke capa unable to find capa.");
    goto failure;
  }
  if (dll_is_empty(&(curr->revoks))) {
    local_domain.print("revoke capa empty revok handles.");
    goto failure;
  }

  // Confidential case.
  if (curr->status == PausedCapa) {
    revok_handle_t* revok = curr->revoks.head;
    if (revok->list.prev != NULL || revok->list.next != NULL) {
      // There should be only one revocation handle for a paused capa.
      local_domain.print("revoke capa revok multiple revok handles.");
      goto failure;
    }
    if (revok->domain != id) {
      // Domain ids do not match.
      local_domain.print("revoke capa domain does not match.");
      goto failure;
    }
    if (tyche_domain_revoke(revok->revok_handle) != 0) {
      local_domain.print("revoke capa failure to revoke.");
      goto failure;
    }
    // Remove and free the handle.
    dll_remove(&(curr->revoks), revok, list);
    local_domain.dealloc(revok);
    if (!dll_is_empty(&(curr->revoks))) {
      local_domain.print("Multiple revok handles in confidential case");
      goto failure;
    }
    // Becomes active again.
    curr->status = ActiveCapa;
    goto attempt_merge;
  }

  // Shared case.
  if (curr->status == SharedCapa) {
    revok_handle_t* revok = NULL;
    dll_foreach(&(curr->revoks), revok, list) {
      if (revok->domain == id) {
        break;
      }
    }
    if (revok == NULL) {
      local_domain.print("revoke capa shared capa null.");
      goto failure;
    }
    if (revok->domain != id) {
      local_domain.print("revoke capa wrong domain id.");
      goto failure;
    }
    if (tyche_domain_revoke(revok->revok_handle) != 0) {
      local_domain.print("revoke capa shared capa failed.");
      goto failure;
    }
    dll_remove(&(curr->revoks), revok, list);
    local_domain.dealloc(revok);
    if (dll_is_empty(&(curr->revoks)) && (curr->is_owned != 0)) {
      curr->status = ActiveCapa;
      goto attempt_merge;
    }
    // Just return
    return 0;
  }
attempt_merge:
  if (curr->status != ActiveCapa) {
    local_domain.print("Attempting to merge non active capa\n");
    goto failure;
  }
  // Attempt a merge on the left.
  prev = curr->list.prev;
  next = curr->list.next;
  if (prev != NULL && prev->end == curr->start
      && prev->is_owned != 0
      && prev->status == ActiveCapa
      && prev->access == curr->access
      && dll_is_empty(&(prev->revoks))) {
    // Opportunity to merge.
    if (tyche_merge_capa(prev->handle, curr->handle) != 0) {
      goto merge_fail;
    } 
    prev->end = curr->end;
    dll_remove(&(local_domain.capabilities), curr, list);
    local_domain.dealloc(curr);
    curr = prev;
  }
  // Attempt a merge on the right.
  if (next != NULL && curr->end == next->start
      && next->is_owned != 0
      && next->status == ActiveCapa
      && next->access == curr->access
      && dll_is_empty(&(prev->revoks))) {
    // Opportunity to merge.
    if (tyche_merge_capa(curr->handle, next->handle) != 0) {
      goto merge_fail;
    }
    curr->end = next->end;
    dll_remove(&(local_domain.capabilities), next, list); 
    local_domain.dealloc(next); 
  }
  return 0;
merge_fail:
  local_domain.print("merge attempt failed");
  return 0;
failure:
  return -1;
}
