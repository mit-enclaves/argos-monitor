#ifndef __DBG_DBG_H__
#define __DBG_DBG_H__

#define _IN_MODULE
#include "tyche_enclave.h"
#undef _IN_MODULE

unsigned long debugging_cr3(void);
void register_cr3(uint64_t cr3);
void debugging_transition(domain_id_t handle);
#endif
