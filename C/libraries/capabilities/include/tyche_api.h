#ifndef __INCLUDE_TYCHE_API_H__
#define __INCLUDE_TYCHE_API_H__

#include "tyche_capabilities.h"
#include "tyche_capabilities_types.h"

/// Copied from the tyche source code.
#define TYCHE_DOMAIN_GET_OWN_ID 0x100
#define TYCHE_DOMAIN_CREATE 0x101
#define TYCHE_DOMAIN_SEAL 0x102
#define TYCHE_DOMAIN_GRANT_REGION 0x103
#define TYCHE_DOMAIN_SHARE_REGION 0x104
#define TYCHE_DOMAIN_REVOK_REGION 0x105
#define TYCHE_REGION_SPLIT 0x200
#define TYCHE_REGION_GET_INFO 0x201
#define TYCHE_REGION_MERGE 0x202
#define TYCHE_CONFIG_NB_REGIONS 0x400
#define TYCHE_CONFIG_READ_REGION 0x401

//TODO we need free spots too.

#define TYCHE_CAPA_NULL ((capa_index_t)0)

/// A type to pass arguments and receive when calling tyche.
typedef struct vmcall_frame_t {
  // Vmcall id.
  unsigned long id;

  // Arguments.
  unsigned long value_1;
  unsigned long value_2;
  unsigned long value_3;
  unsigned long value_4;

  // Results.
  unsigned long ret_1;
  unsigned long ret_2;
  unsigned long ret_3;
  unsigned long ret_4;
} vmcall_frame_t;

// ——————————————————————————— Internal functions ——————————————————————————— //

unsigned long translate_access(capability_type_t tpe);

// —————————————————————————————————— API ——————————————————————————————————— //
int tyche_call(vmcall_frame_t* frame);
int tyche_get_domain_id(domain_id_t* domain);
int tyche_create_domain(domain_id_t* handle);
int tyche_read_capa(capability_t* capa);
int tyche_split_capa(paddr_t handle, paddr_t split_addr, paddr_t* new_handle);
int tyche_grant_capa(domain_id_t target, paddr_t handle, capability_type_t tpe, paddr_t* new_handle);
int tyche_share_capa(domain_id_t target, paddr_t handle, capability_type_t tpe, paddr_t* new_handle);
int tyche_merge_capa(paddr_t h1, paddr_t h2);
int tyche_domain_seal(domain_id_t handle, paddr_t cr3, paddr_t entry, paddr_t stack, capa_index_t* invoke_handle);
int tyche_domain_revoke(paddr_t handle);

#endif
