#ifndef __INTERNAL_TYCHE_VMCALL_H__
#define __INTERNAL_TYCHE_VMCALL_H__

#include "enclave.h"

int tyche_domain_create(struct enclave_t* encl);
int tyche_split_grant(struct enclave_t* enclave, struct pa_region_t* region);
int tyche_seal_enclave(struct enclave_t* enclave);
int tyche_revoke_region(domain_id_t dom, paddr_t start, paddr_t end);
#endif
