#ifndef __INTERNAL_PROCESS_H__
#define __INTERNAL_PROCESS_H__
#include "enclave.h"

// ————————————————————— Information Passed via Walker —————————————————————— //

struct walker_info_t {
  struct region_t* region;
  int success;
};

int init_page_walker(void);
int walk_and_collect_region(struct region_t* region);

#endif
