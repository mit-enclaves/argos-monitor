#include "tyche_api.h"
#include "tyche_capabilities_types.h"

unsigned long translate_access(capability_type_t tpe)
{
  switch(tpe) {
    case Confidential:
    case Shared:
      return (CAPA_READ|CAPA_EXEC|CAPA_WRITE);
    case ConfidentialRO:
    case SharedRO:
      return (CAPA_READ);
    case ConfidentialRW:
    case SharedRW:
      return (CAPA_READ|CAPA_WRITE);
    case ConfidentialRX:
    case SharedRX:
      return (CAPA_READ|CAPA_EXEC);
    default:
      break;
  }
  return CAPA_NONE;
}

/// Simple generic vmcall implementation.
int tyche_call(vmcall_frame_t* frame)
{
  unsigned long result = 1;
  asm volatile(
    "movq %5, %%rax\n\t"
    "movq %6, %%rcx\n\t"
    "movq %7, %%rdx\n\n"
    "movq %8, %%rsi\n\t"
    "movq %9, %%r9\n\t"
    "vmcall\n\t"
    "movq %%rax, %0\n\t"
    "movq %%rcx, %1\n\t"
    "movq %%rdx, %2\n\t"
    "movq %%rsi, %3\n\t"
    "movq %%r9, %4\n\t"
    : "=rm" (result), "=rm" (frame->ret_1), "=rm" (frame->ret_2), "=rm" (frame->ret_3), "=rm" (frame->ret_4)
    : "rm" (frame->id), "rm" (frame->value_1), "rm" (frame->value_2), "rm" (frame->value_3), "rm" (frame->value_4) 
    : "rax", "rcx", "rdx", "rsi", "r9", "memory");

  return (int)result;
} 

int tyche_get_domain_id(domain_id_t* domain)
{
  vmcall_frame_t frame;
  if (domain == NULL) {
    return -1;
  }
  frame.id= TYCHE_DOMAIN_GET_OWN_ID;
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  *domain = frame.ret_1;
  return 0;
}

int tyche_create_domain(domain_id_t* handle)
{
  vmcall_frame_t frame;
  if (handle == NULL) {
    return -1;
  }
  frame.id = TYCHE_DOMAIN_CREATE;
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  *handle = frame.ret_1;
  return 0;
}

int tyche_read_capa(capability_t* capa)
{
  vmcall_frame_t frame;
  if (capa == NULL) {
    return -1;
  } 

  frame.id = TYCHE_REGION_GET_INFO;
  frame.value_1 = capa->handle;
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  capa->start = frame.ret_1;
  capa->end = frame.ret_2;
  capa->is_owned = frame.ret_3 & TYCHE_OWNED;
  capa->is_shared = frame.ret_3 & TYCHE_SHARED;
  capa->access = frame.ret_4;
  dll_init_elem(capa, list);
  dll_init_list(&(capa->revoks));
  return 0;
}

int tyche_split_capa(paddr_t handle, paddr_t split_addr, paddr_t* new_handle)
{
  vmcall_frame_t frame;
  int result = 0;
  if (new_handle == NULL) {
    return -1;
  }
  frame.id= TYCHE_REGION_SPLIT;
  frame.value_1 = handle;
  frame.value_2 = split_addr;
  result = tyche_call(&frame);
  if (result != 0) {
    return result;
  }
  *new_handle = frame.ret_1;
  return 0;
}

int tyche_grant_capa(domain_id_t target, paddr_t handle, capability_type_t tpe, paddr_t* new_handle)
{
  //We should change that.
  vmcall_frame_t frame;
  if (new_handle == NULL) {
    return -1;
  }
  frame.id = TYCHE_DOMAIN_GRANT_REGION;
  frame.value_1 = target;
  frame.value_2 = handle;
  frame.value_3 = translate_access(tpe);
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  *new_handle = frame.ret_1;
  return 0;
}

int tyche_share_capa(domain_id_t target, paddr_t handle, capability_type_t tpe, paddr_t* new_handle)
{
  vmcall_frame_t frame;
  if (new_handle == NULL) {
    return -1;
  }
  frame.id = TYCHE_DOMAIN_SHARE_REGION;
  frame.value_1 = target;
  frame.value_2 = handle;
  frame.value_3 = translate_access(tpe);
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  *new_handle = frame.ret_1;
  return 0;
}

int tyche_merge_capa(paddr_t h1, paddr_t h2)
{
  vmcall_frame_t frame; 
  frame.id = TYCHE_REGION_MERGE;
  frame.value_1 = h1;
  frame.value_2 = h2;
  frame.value_3 = 0;
  frame.value_4 = 0;
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  return 0;
}

int tyche_domain_seal(domain_id_t handle, paddr_t cr3, paddr_t entry, paddr_t stack, capa_index_t* invoke_capa)
{
  vmcall_frame_t frame;
  frame.id = TYCHE_DOMAIN_SEAL;
  frame.value_1 = handle;
  frame.value_2 = cr3;
  frame.value_3 = entry;
  frame.value_4 = stack;
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  *invoke_capa = frame.ret_1;
  return 0;
}

int tyche_domain_revoke(paddr_t handle)
{
  vmcall_frame_t frame;
  frame.id = TYCHE_DOMAIN_REVOK_REGION;
  frame.value_1 = handle;
  frame.value_2 = 0;
  frame.value_3 = 0;
  frame.value_4 = 0;
  if (tyche_call(&frame) != 0) {
    return -1;
  }
  return 0;
}
