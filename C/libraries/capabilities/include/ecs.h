#ifndef __INCLUDE_HARDWARE_CAPABILITIES_H__
#define __INCLUDE_HARDWARE_CAPABILITIES_H__

#include "tyche_capabilities_types.h"

// —————————————————————————————————— API ——————————————————————————————————— //

/// Enumerate the next capability with index >= idx.
int enumerate_capa(capa_index_t idx, capability_t* capa);

#endif
