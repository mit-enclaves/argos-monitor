#ifndef __INCLUDE_ENCL_RT_H__
#define __INCLUDE_ENCL_RT_H__

#include "tyche_enclave.h"

void domain_gate_vmcall(tyche_encl_handle_t handle, void (*function)(void*), void* args);

#endif
