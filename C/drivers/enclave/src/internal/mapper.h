#ifndef __INTERNAL_MAPPER_H__
#define __INTERNAL_MAPPER_H__

#include "enclave.h"
#include "x86_64_pt.h"

typedef struct map_info_t {
  // Intermediary flags to be used in the page tables.
  entry_t intermed_flags;
  // The region we are currently mapping.
  struct region_t* region;
  // A pointer to the current physical page to use.
  struct pa_region_t* pa_region;
  // A backward edge to the current profile.
  pt_profile_t* profile;
  // The enclave we are currently handling.
  struct enclave_t* enclave;
} map_info_t;

int build_enclave_cr3(struct enclave_t* encl);

#endif
