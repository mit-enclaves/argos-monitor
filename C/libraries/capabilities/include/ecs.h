#ifndef __INCLUDE_HARDWARE_CAPABILITIES_H__
#define __INCLUDE_HARDWARE_CAPABILITIES_H__

#include "tyche_capabilities_types.h"
///! This file describes the API to talk with tyche when reading ECS.
/// It basically abstracts a very simple monitor API that reads 64 bits at
/// a given offset.
///
/// Conceptually, it is just an array of 64 bits entries.

// ————————————————————————— Size-dependent offsets ————————————————————————— //
#define TYCHE_ECS_FIRST_ENTRY ((capa_index_t)0)

// —————————————————————————————————— API ——————————————————————————————————— //

/// Read the size of the ECS.
int ecs_read_size(capa_index_t* size);

/// Read the entry at idx from the ECS.
int ecs_read_entry(capa_index_t idx, paddr_t* entry);

#endif
