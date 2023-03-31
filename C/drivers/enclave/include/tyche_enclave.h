#ifndef __INCLUDE_TYCHE_ENCLAVE_H__
#define __INCLUDE_TYCHE_ENCLAVE_H__

#ifdef _IN_MODULE
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#include "tyche_capabilities_types.h"

// ———————————————————— Constants Defined in the Module ————————————————————— //
#define TE_READ ((uint64_t)CAPA_READ)
#define TE_WRITE ((uint64_t)CAPA_WRITE)
#define TE_EXEC ((uint64_t)CAPA_EXEC)
#define TE_USER ((uint64_t)(CAPA_MAX << 1))
#define TE_DEFAULT ((uint64_t)(TE_READ | TE_WRITE | TE_EXEC))

// —————————————————————— Types Exposed by the Library —————————————————————— //
typedef domain_id_t tyche_encl_handle_t;

/// Message type to create a new enclave.
struct tyche_encl_create_t {
  tyche_encl_handle_t handle;
};

typedef capability_type_t tyche_encl_mapping_t;

/// Message type to add a new region.
struct tyche_encl_add_region_t {
  /// Unique enclave reference capability.
  tyche_encl_handle_t handle;

  /// Start address. Must be page aligned.
  uint64_t start;

  /// End address. Must be page aligned.
  uint64_t end;

  /// Source for the content of the region.
  uint64_t src;

  /// Protection flags (RWXU) for this region.
  uint64_t flags;

  /// Type of mapping: Confidential or Shared.
  tyche_encl_mapping_t tpe;

  /// Not read by the module, but can be used by user level libraries for
  /// extra information.
  void* extra;
};

/// Structure of the commit message.
struct tyche_encl_commit_t {
  /// The driver handle.
  tyche_encl_handle_t handle;

  /// The handle to reference the domain.
  domain_id_t domain_handle;

  /// The pointer to the stack.
  uint64_t stack;

  /// The entry point.
  uint64_t entry;
};

/// Structure to describe a transition.
struct tyche_encl_transition_t {
  /// The enclave handle to transition into.
  tyche_encl_handle_t handle;

  /// Argument for this transition.
  void* args;
};

// ——————————————————————————— Tyche Enclave IOCTL API —————————————————————— //
#define TYCHE_ENCLAVE_DBG _IOR('a', 'a', uint64_t*)
#define TYCHE_ENCLAVE_CREATE _IOR('a', 'b', struct tyche_encl_create_t*)
#define TYCHE_ENCLAVE_ADD_REGION _IOW('a', 'c', struct tyche_encl_add_region_t*)
#define TYCHE_ENCLAVE_COMMIT _IOWR('a', 'd', struct tyche_encl_commit_t*)
#define TYCHE_ENCLAVE_ADD_STACK _IOW('a', 'e', struct tyche_encl_add_region_t*)
#define TYCHE_TRANSITION _IOR('a', 'f', struct tyche_encl_transition_t*)
#define TYCHE_ENCLAVE_DELETE _IOR('a', 'g', tyche_encl_handle_t)

#endif
