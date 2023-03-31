#ifndef __INCLUDE_TYCHE_CAPABILITIES_TYPES_H__
#define __INCLUDE_TYCHE_CAPABILITIES_TYPES_H__

#ifndef NULL
#define NULL ((void*)0)
#endif

/// Internal definition of our types so we can move to 32 bits.
typedef long long unsigned int paddr_t;

/// Internal definition of domain id.
typedef unsigned long domain_id_t;

/// Internal definition of index.
typedef unsigned long capa_index_t;

//TODO change this to reflect revocation better.
/// Valid types for a capability.
typedef enum capability_type_t {
  MinTpe = 0,
  SharedRO = 0,
  SharedRW = 1,
  SharedRX = 2,
  Shared = 3,
  ConfidentialRO = 4,
  ConfidentialRW = 5,
  ConfidentialRX = 6,
  PtEntry = 7,
  Confidential = 7,
  MaxTpe = 7,
} capability_type_t;

/// Predefined values for capabilities
#define CAPA_NONE ((unsigned long)0)
#define CAPA_READ ((unsigned long)1 << 0)
#define CAPA_WRITE ((unsigned long)1 << 1)
#define CAPA_EXEC ((unsigned long)1 << 2)
#define CAPA_REVOK ((unsigned long)1 << 3)
#define CAPA_MAX CAPA_REVOK

#define TYCHE_OWNED ((unsigned long)0x1)
#define TYCHE_SHARED ((unsigned long)0x2)

#endif
