#include "ecs.h"
#include "tyche_api.h"

int enumerate_capa(capa_index_t *idx, capability_t *capa) {
  vmcall_frame_t frame;
  if (capa == NULL) {
    goto fail;
  }
  frame.vmcall = TYCHE_ENUMERATE;
  frame.arg_1 = *idx;
  if (tyche_call(&frame) != 0) {
    goto fail;
  }

  // Next token
  *idx = frame.value_4;
  if (*idx == 0) {
    // No more capa
    goto fail;
  }

  // Setup the capability with the values in the registers.
  capa->local_id = frame.value_4 - 1; // value_4 is the **next** token
  capa->capa_type = frame.value_3 & 0xFF;

  // Parse the information encoded from AccessRights.as_bits().
  switch (capa->capa_type) {
  case Region:
    capa->info.region.start = frame.value_1;
    capa->info.region.end = frame.value_2;
    capa->info.region.flags = frame.value_3 << 8;
    break;
  case Management:
    capa->info.management.id = frame.value_1;
    break;
  case Channel:
    capa->info.channel.id = frame.value_1;
    break;
  case Switch:
    capa->info.transition.id = frame.value_1;
    break;
  }

  // Everything went well.
  return 0;
fail:
  return -1;
}
