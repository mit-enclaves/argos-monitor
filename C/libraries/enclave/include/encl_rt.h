#ifndef __INCLUDE_ENCL_RT_H__
#define __INCLUDE_ENCL_RT_H__

// Define the tyche_encl_handle_t here to avoid dep on the driver.
typedef unsigned long tyche_encl_handle_t;

void domain_gate_vmcall(tyche_encl_handle_t handle, void (*function)(void*), void* args);

#endif
