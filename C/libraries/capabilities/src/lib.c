#include "tyche_capabilities_types.h"
#include "tyche_capabilities.h"
#include "tyche_api.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
domain_t local_domain;

// ———————————————————————— Private helper functions ———————————————————————— //
void local_memcpy(void* dest, void *src, unsigned long n) {
  unsigned long i = 0;
  char *csrc = (char*) src;
  char *cdest = (char*) dest;
  for (i = 0; i < n; i++) {
    cdest[i] = csrc[i];
  }
}

void local_memset(void* dest, unsigned long n) {
  unsigned long i = 0;
  char *cdest = (char*) dest;
  for (i = 0; i < n; i++) {
    cdest[i] = 0;
  }
}
// —————————————————————————————— Public APIs ——————————————————————————————— //


int init(capa_alloc_t allocator, capa_dealloc_t deallocator, capa_dbg_print_t print)
{
  capa_index_t i = 0;
  if (allocator == 0 || deallocator == 0 || print == 0) {
    goto fail;
  }
  // Set the local domain's functions.
  local_domain.alloc = allocator;
  local_domain.dealloc = deallocator;
  local_domain.print = print;
  local_domain.self = NULL;
  dll_init_list(&(local_domain.capabilities));
  dll_init_list(&(local_domain.children));

  // Start enumerating the domain's capabilities.
  for (i = 0; i < CAPAS_PER_DOMAIN; i++) {
    capability_t tmp_capa;
    capability_t *capa = NULL;
    if (enumerate_capa(i, &tmp_capa) != 0) {
      // Unable to read, move on. 
      continue; 
    };
    capa = (capability_t*) (local_domain.alloc(sizeof(capability_t)));
    if (capa == NULL) {
      local_domain.print("Unable to allocate a capability!\n");
      goto failure;
    }
    // Copy the capability into the dynamically allocated one.
    local_memcpy(capa, &tmp_capa, sizeof(capability_t));
    dll_init_elem(capa, list);

    // Look for the self capability.
    if (capa->capa_type == Resource &&
        capa->resource_type == Domain &&
        capa->access.domain.status == Sealed) {
      if (local_domain.self != NULL) {
        // We have two sealed capabilities this doesn't make sense.
        local_domain.print("Found two sealed capa for the current domain.\n");
        goto failure;
      }
      local_domain.self = capa;
      // Do not add the self capability to the list.
      continue;
    }

    // Add the capability to the list.
    dll_add(&(local_domain.capabilities), capa, list);
  }

  // For debugging, remove afterwards.
  local_domain.print("[init] success");
  return SUCCESS;
failure:
  while(!dll_is_empty(&local_domain.capabilities))
  {
    capability_t* capa = local_domain.capabilities.head;
    dll_remove(&(local_domain.capabilities), capa, list);
    local_domain.dealloc((void*)capa);
  }
fail: 
  return FAILURE;
}

int create_domain(domain_id_t* id, usize spawn, usize comm)
{
  capa_index_t new_self = -1;
  capability_t* child_capa = NULL;
  capability_t* revocation_capa = NULL; 
  child_domain_t* child = NULL;
  
  local_domain.print("[create_domain] start");
  // Initialization was not performed correctly.
  if (local_domain.self == NULL || id == NULL) {
    local_domain.print("Error[create_domain] self is null or id null.");
    goto fail;
  }

  // Perform allocations.
  child = (child_domain_t*) local_domain.alloc(sizeof(child_domain_t));
  if (child == NULL) {
    local_domain.print("Error[create_domain] failed to allocate child.");
    goto fail;
  }
  revocation_capa = (capability_t*) local_domain.alloc(sizeof(capability_t));
  if (revocation_capa == NULL) {
    local_domain.print("Error[create_domain] failed to allocate revocation.");
    goto fail_child;
  }
  child_capa = (capability_t*) local_domain.alloc(sizeof(capability_t));
  if (child_capa == NULL) {
    local_domain.print("Error[create_domain] failed to allocate child_capa.");
    goto fail_revocation; 
  }

  // Create the domain.
  if (tyche_create_domain(
        &new_self, 
        &(child_capa->local_id),
        &(revocation_capa->local_id),
        spawn, comm) != 0) {
    local_domain.print("Error[create_domain] failed to create domain.");
    goto fail;
  }

  // Populate the capabilities.
  if (enumerate_capa(new_self, local_domain.self) != 0) {
    local_domain.print("Error[create_domain] enumerate left failed.");
    goto fail_child_capa;
  }
  if (enumerate_capa(child_capa->local_id, child_capa) != 0) {
    local_domain.print("Error[create_domain] enumerate child_capa failed.");
    goto fail_child_capa;
  }
  if (enumerate_capa(revocation_capa->local_id, revocation_capa) != 0) {
    local_domain.print("Error[create_domain] enumerate revocation_capa failed.");
    goto fail_child_capa;
  }

  // Initialize the child domain.
  child->id = local_domain.id_counter++;
  child->revoke = revocation_capa;
  child->manipulate = child_capa; 
  dll_init_list(&(child->revocations));
  dll_init_elem(child, list);
  revocation_capa->left = NULL; //local_domain.self;
  revocation_capa->right = NULL; //child_capa;
  //child_capa->parent = revocation_capa;
  //local_domain.self->parent = revocation_capa;

  // Add the child to the local_domain.
  dll_add(&(local_domain.children), child, list);

  //TODO not sure about that.
  // Add the capabilities to the local domain.
  dll_init_elem(revocation_capa, list);
  dll_init_elem(child_capa, list);
  //dll_add(&(local_domain.capabilities), revocation_capa, list);
  //dll_add(&(local_domain.capabilities), child_capa, list);

  // All done!
  *id = child->id;
  local_domain.print("[create_domain] Success");
  return SUCCESS;

  // Failure paths.
fail_child_capa:
  local_domain.dealloc(child_capa);
fail_revocation:
  local_domain.dealloc(revocation_capa);
fail_child:
  local_domain.dealloc(child);
fail:
  return FAILURE;
}

int seal_domain(
    domain_id_t id,
    usize core_map,
    usize cr3,
    usize rip,
    usize rsp)
{
  child_domain_t* child = NULL;
  capability_t* new_unsealed = NULL;
  capability_t* channel = NULL, *transition = NULL;
  capa_index_t to_seal = 0;
  usize tpe = 0;
  transition_t *trans_wrapper = NULL;

  local_domain.print("[seal_domain] start");
  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    local_domain.print("Error[grant_region]: child not found."); 
    goto failure;
  }

  transition = (capability_t*) local_domain.alloc(sizeof(capability_t));
  if (transition == NULL) {
    local_domain.print("Error[seal_domain]: could not allocate transition capa.");
    goto failure;
  }
 
  trans_wrapper = (transition_t*) local_domain.alloc(sizeof(transition_t));
  if (trans_wrapper == NULL) {
    local_domain.print("Error[seal_domain]: Unable to allocate transition_t wrapper");
    goto failure_transition;
  }
  
  // Create the transfer.
  if (child->manipulate->access.domain.status != Unsealed) {
    local_domain.print("Error[seal_domain]: we do not have an unseal capa.");
    goto failure_dealloc;
  }
  tpe = Unsealed ;
  if (child->manipulate->access.domain.info.capas.spawn != 0) {
    tpe |= Spawn;
  }
  if (child->manipulate->access.domain.info.capas.comm != 0) {
    tpe |= Comm;
  }
  if (duplicate_capa(
        &new_unsealed, &channel, child->manipulate, 
        tpe, 0, 0, Channel, 0, 0) != SUCCESS) {
    local_domain.print("Error[seal_domain] unable to create a channel.");
    goto failure_dealloc;
  }
  
  // Cleanup phase:
  // We can get rid of: 
  // 1. Manipulate -> it was an unsealed, it will get destroyed by revoke_domain.
  // 2. new_unsealed -> it will get revoked as well.
  // Then we have to fix all the tree pointers.
  dll_remove(&(local_domain.capabilities), new_unsealed, list);
  to_seal = new_unsealed->local_id;
  local_domain.dealloc(new_unsealed);
  local_domain.dealloc(child->manipulate);

  // Fix the child's manipulate.
  dll_remove(&(local_domain.capabilities), channel, list);
  child->manipulate = channel;
  child->manipulate->parent = NULL;

  // Now seal.
  if (tyche_seal(&(transition->local_id), to_seal,
        core_map, cr3, rip, rsp) != SUCCESS) {
    local_domain.print("Error[seal_domain]: error sealing domain.");
    goto failure_dealloc;
  }

  if (enumerate_capa(transition->local_id, transition) != SUCCESS) {
    local_domain.print("Error[seal_domain]: error enumerating transition.");
    goto failure_dealloc;
  }


  trans_wrapper->lock = TRANSITION_UNLOCKED;
  trans_wrapper->transition = transition; 
  dll_init_elem(trans_wrapper, list);
  dll_add(&(child->transitions), trans_wrapper, list);
  
  // All done !
  local_domain.print("[seal_domain] Success");
  return SUCCESS;
failure_dealloc:
  local_domain.dealloc(trans_wrapper);
failure_transition:
  local_domain.dealloc(transition);
failure:
  return FAILURE;
}

int duplicate_capa(
    capability_t** left,
    capability_t** right,
    capability_t* capa,
    usize a1_1,
    usize a1_2,
    usize a1_3,
    usize a2_1,
    usize a2_2,
    usize a2_3) {
  if (left == NULL || right == NULL || capa == NULL) {
    goto failure;
  }

  // Attempt to allocate left and right.
  *left = (capability_t*) local_domain.alloc(sizeof(capability_t));
  if (*left == NULL) {
    local_domain.print("Error[duplicate_capa] left alloc failed.");
    goto failure;
  }
  *right = (capability_t*) local_domain.alloc(sizeof(capability_t));
  if (*right == NULL) {
    local_domain.print("Error[duplicate_capa] right alloc failed.");
    goto fail_left;
  }

  // Call duplicate.
  if (tyche_duplicate(
        &((*left)->local_id), &((*right)->local_id), capa->local_id,
        a1_1, a1_2, a1_3, a2_1, a2_2, a2_3 ) != SUCCESS) {
    local_domain.print("Error[duplicate_capa] duplicate rejected.");
    goto fail_right; 
  }

  // Update the capability.
  if (enumerate_capa(capa->local_id, capa) != SUCCESS) {
    local_domain.print("We failed to enumerate the root of a duplicate!");
    goto fail_right;
  }
  capa->left = *left;
  capa->right = *right;
  
  // Initialize the left.
  if(enumerate_capa((*left)->local_id, *left) != SUCCESS) {
    local_domain.print("We failed to enumerate the left of duplicate!");
    goto fail_right;
  }
  dll_init_elem((*left), list);
  dll_add(&(local_domain.capabilities), (*left), list); 
  (*left)->parent = capa;
  (*left)->left = NULL;
  (*left)->right = NULL;

  // Initialize the right.
  if (enumerate_capa((*right)->local_id, (*right)) != SUCCESS) {
    local_domain.print("We failed to enumerate the right of duplicate!");
    goto fail_right;
  }
  dll_init_elem((*right), list);
  dll_add(&(local_domain.capabilities), (*right), list);
  (*right)->parent = capa;
  (*right)->left = NULL;
  (*right)->right = NULL;

  // All done!
  return SUCCESS;

  // Failure paths.
fail_right:
  local_domain.dealloc(*right);
fail_left:
  local_domain.dealloc(*left);
failure:
  return FAILURE;
}

//TODO: for the moment only handle the case where the region is fully contained
//within one capability.
int grant_region(domain_id_t id, paddr_t start, paddr_t end, memory_access_right_t access) {
  child_domain_t* child = NULL;
  capability_t* capa = NULL;

  local_domain.print("[grant_region] start");
  // Quick checks.
  if (start >= end) {
    local_domain.print("Error[grant_region]: start is greater or equal to end.\n");
    goto failure;
  }

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    local_domain.print("Error[grant_region]: child not found."); 
    goto failure;
  }

  // Now attempt to find the capability.
  dll_foreach(&(local_domain.capabilities), capa, list) {
    if (capa->capa_type != Resource || capa->resource_type != Region) {
      continue;
    }
    if ((dll_contains(capa->access.region.start, capa->access.region.end, start)) && 
        capa->access.region.start <= end && capa->access.region.end >= end) {
      // Found the capability.
      break;
    }
  }

  // We were not able to find the capability.
  if (capa == NULL) {
    local_domain.print("Error[grant_region] unable to find the containing capa.");
    goto failure;
  }

  // The region is in the middle, requires two splits.
  if (capa->access.region.start < start && capa->access.region.end > end) {
    // Middle case.
    // capa: [s.......................e]
    // grant:     [m.....me]
    // Duplicate such that we have [s..m] [m..me..e]
    // And then update capa to be equal to the right
    capability_t* left = NULL, *right = NULL;
    if (duplicate_capa(&left, &right, capa,
          capa->access.region.start, start, capa->access.region.flags,
          start, capa->access.region.end, capa->access.region.flags) != SUCCESS) {
      local_domain.print("Error[grant_region] middle case duplicate failed.");
      goto failure;
    }
    // Update the capa to point to the right.
    capa = right;
  }

  // Requires a duplicate.
  if ((capa->access.region.start == start && capa->access.region.end > end) ||
      (capa->access.region.start < start && capa->access.region.end == end)) {
    paddr_t s = 0, m = 0, e = 0;
    capability_t* left = NULL, *right = NULL;
    capability_t** to_grant = NULL; 

    if (capa->access.region.start == start && capa->access.region.end > end) {
      // Left case.
      // capa: [s ............e].
      // grant:[s.......m].
      // duplicate: [s..m] - [m..e]
      // Grant the first portion.
      s = capa->access.region.start;
      m = end;
      e = capa->access.region.end;
      to_grant = &left;
    } else {
      // Right case.
      // capa: [s ............e].
      // grant:      [m.......e].
      // duplicate: [s..m] - [m..e]
      // Grant the second portion.
      s = capa->access.region.start;
      m = start;
      e = capa->access.region.end;
      to_grant = &right;
    }

    // Do the duplicate.
    if (duplicate_capa(&left, &right, capa, s, m, capa->access.region.flags,
          m, e, capa->access.region.flags) != SUCCESS) {
      local_domain.print("Error[grant_region] left or right duplicate case failed.");
      goto failure;
    }
   
    // Now just update the capa to grant.
    capa = *to_grant;
  } 

  // At this point, capa should be a perfect overlap.
  if (capa == NULL || 
      !(capa->access.region.start == start && capa->access.region.end == end)) {
    goto failure;
  }

  if (tyche_grant(child->manipulate->local_id, capa->local_id,
        start, end, (usize) access) != SUCCESS) {
    goto failure;
  }

  if (enumerate_capa(capa->local_id, capa) != SUCCESS) {
    goto failure;
  }

  // Now we update the capabilities.
  dll_remove(&(local_domain.capabilities), capa, list);
  if (capa->capa_type != Revocation) {
    local_domain.print("[DBG] not a revocation 2");
  }
  dll_add(&(child->revocations), capa, list);

  // We are done!
  local_domain.print("[grant_region] Success");
  return SUCCESS;
failure:
  return FAILURE;
}


int share_region(
    domain_id_t id, paddr_t start, paddr_t end, memory_access_right_t access) {
  child_domain_t* child = NULL;
  capability_t* capa = NULL, *left = NULL, *right = NULL;

  local_domain.print("[share_region] start");
  // Quick checks.
  if (start >= end) {
    local_domain.print("Error[share_region]: start is greater or equal to end.\n");
    goto failure;
  }

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    local_domain.print("Error[share_region]: child not found."); 
    goto failure;
  }

  // Now attempt to find the capability.
  dll_foreach(&(local_domain.capabilities), capa, list) {
    if (capa->capa_type != Resource || capa->resource_type != Region) {
      continue;
    }
    // TODO check dll_contains, might fail on end.
    if (dll_contains(capa->access.region.start, capa->access.region.end, start) && 
        capa->access.region.start <= end &&  capa->access.region.end >= end) {
      // Found the capability.
      break;
    }
  }

  // We were not able to find the capability.
  if (capa == NULL) {
    goto failure;
  }

  // A share is less complex than a grant because it doesn't require carving out.
  // We still create a capability that matches exactly the desired interval.
  // This allows to revoke that region independently of subsequent shares.
  if (duplicate_capa(&left, &right, capa, capa->access.region.start,
        capa->access.region.end, capa->access.region.flags,
        start, end, (usize) capa->access.region.flags) != SUCCESS) {
    goto failure;
  }

  // We implement the share as a grant of the cut out region.
  if (tyche_grant(child->manipulate->local_id, right->local_id,
        start, end, (usize) access) != SUCCESS) {
    local_domain.print("Failed sharing the region with the domain.");
    goto failure;
  }

  // Now we update the capabilities.
  if (enumerate_capa(right->local_id, right) != SUCCESS) {
    local_domain.print("We failed enumerating the revocation after share.");
    goto failure;
  }
  dll_remove(&(local_domain.capabilities), right, list);
  if (right->capa_type != Revocation) {
    local_domain.print("[DBG] not a revocation 3");
  }
  dll_add(&(child->revocations), right, list);

  // All done!
  local_domain.print("[share_region] Success");
  return SUCCESS;
failure:
  return FAILURE;
}

// TODO for now we only handle exact matches.
int internal_revoke(child_domain_t* child, capability_t* capa)
{
  if (child == NULL || capa == NULL) {
    local_domain.print("Error[internal_revoke]: null args.");
    goto failure;
  }

  if (capa->capa_type != Revocation) {
    local_domain.print("Error[internal revoke] supplied capability is not a revocation");
    goto failure;
  }

  if (tyche_revoke(capa->local_id) != SUCCESS) {
    goto failure;
  }
  
  if (enumerate_capa(capa->local_id, capa) != SUCCESS) {
    local_domain.print("Error[internal_revoke]: unable to enumerate the revoked capa");
    goto failure;
  }

  // Remove the capability and add it back to the local domain.
  dll_remove(&(child->revocations), capa, list);
  dll_add(&(local_domain.capabilities), capa, list);

  // Check if we can merge everything back.
  while(capa->parent != NULL && 
     ((capa->parent->right == capa &&
        capa->parent->left != NULL && 
        capa->parent->left->capa_type == Resource) ||
     (capa->parent->left == capa && 
      capa->parent->right != NULL &&
      capa->parent->right->capa_type == Resource))) {
    capability_t *parent = capa->parent;
    if (tyche_revoke(parent->local_id) != SUCCESS) {
      goto failure;
    }
    dll_remove(&(local_domain.capabilities), (parent->right), list);
    dll_remove(&(local_domain.capabilities), (parent->left), list);
    local_domain.dealloc(parent->left);
    local_domain.dealloc(parent->right);
    parent->left = NULL;
    parent->right = NULL;
    if (enumerate_capa(parent->local_id, parent) != SUCCESS) {
      local_domain.print("Error[internal_revoke]: unable to enumerate after the merge.");
      goto failure;
    }
    capa = parent;
  }

  // All done!
  local_domain.print("[internal_revoke] success");
  return SUCCESS;
failure:
  local_domain.print("[internal_revoke] failure");
  return FAILURE;
}

int revoke_region(domain_id_t id, paddr_t start, paddr_t end)
{
  child_domain_t* child = NULL;
  capability_t* capa = NULL;
  
  local_domain.print("[revoke_region] start");
  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    local_domain.print("Error[revoke_region]: child not found."); 
    goto failure;
  }

  // Try to find the region.
  dll_foreach(&(child->revocations), capa, list) {
    if (capa->resource_type == Region && capa->access.region.start == start 
        && capa->access.region.end == end) {
      // Found it!
      break;
    } 
  }
  if (capa == NULL) {
    local_domain.print("Error[revoke_region]: unable to find region to revoke.");
    goto failure;
  }
  if (internal_revoke(child, capa) != SUCCESS) {
    goto failure;
  }
  local_domain.print("[revoke_region] success");
  return SUCCESS;
failure:
  local_domain.print("[revoke_region] failure");
  return FAILURE;
}

//TODO nothing thread safe in this implementation for the moment.
int switch_domain(domain_id_t id, void* args)
{
  child_domain_t* child = NULL;
  transition_t* wrapper = NULL;
  local_domain.print("[switch_domain] start");

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    local_domain.print("Error[switch_domain]: child not found."); 
    goto failure;
  }

  // Acquire a transition handle.
  dll_foreach(&(child->transitions), wrapper, list) {
    if (wrapper->lock == TRANSITION_UNLOCKED) {
      wrapper->lock = TRANSITION_LOCKED;
      break;
    }
  }
  if (wrapper == NULL) {
    local_domain.print("Error[switch_domain]: Unable to find a transition handle!");
    goto failure;
  }
  if (tyche_switch(wrapper->transition->local_id, NO_CPU_SWITCH, args) != SUCCESS) {
    local_domain.print("Error[switch_domain]: failed to perform a switch");
    goto failure;
  }
  local_domain.print("[switch_domain] Came back from the switch");
  // We are back from the switch, unlock the wrapper.
  wrapper->lock = TRANSITION_UNLOCKED;
  return SUCCESS;
failure:
  return FAILURE;
}

int revoke_domain(domain_id_t id)
{
  child_domain_t* child = NULL;
  capability_t* capa = NULL;
  transition_t* wrapper = NULL;
  
  local_domain.print("[revoke_domain] start");

  // Find the target domain.
  dll_foreach(&(local_domain.children), child, list) {
    if (child->id == id) {
      // Found the right one.
      break;
    }
  }

  // We were not able to find the child.
  if (child == NULL) {
    local_domain.print("Error[revoke_domain]: unable to find the child.");
    goto failure;
  }

  // First go through all the revocations.
  while (!dll_is_empty(&(child->revocations))) {
    capa = child->revocations.head;
    if (capa->left != NULL) {
      // By construction this should never happen.
      local_domain.print("Error[revoke_domain]: The revoked capa has non empty left.");
      goto failure;
    }
    if (capa->right != NULL) {
      // By construction this should never happen.
      local_domain.print("Error[revoke_domain]: The revoked capa has non empty right.");
      goto failure;
    }
    if (internal_revoke(child, capa) != SUCCESS) {
      local_domain.print("Error[revoke_domain] unable to revoke a capability.");
      goto failure;
    }
  }
  // Take care of the transitions + manipulate.
  // No need to call revoke, they should be handled by the cascading revocation.
  while (!dll_is_empty(&(child->transitions))) {
    wrapper = child->transitions.head;
    capa = wrapper->transition;
    dll_remove(&(child->transitions), wrapper, list);
    local_domain.dealloc(capa);
    local_domain.dealloc(wrapper);
  }
  // Remove the manipulate too.
  local_domain.dealloc(child->manipulate);

  if (tyche_revoke(child->revoke->local_id) != SUCCESS) {
    goto failure;
  }
  if (enumerate_capa(child->revoke->local_id, local_domain.self) != SUCCESS) {
    local_domain.print("Error[revoke_domain] Unable to enumerate self");
    goto failure;
  }
  local_domain.dealloc(child->revoke);
  dll_remove(&(local_domain.children), child, list);
  local_domain.dealloc(child);
  
  local_domain.print("[revoke_domain] success");
  return SUCCESS;
failure:
  local_domain.print("[revoke_domain] failure");
  return FAILURE;
}
