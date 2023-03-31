#include "ecs.h"
#include "tyche_api.h"

int enumerate_capa(capa_index_t idx, capability_t* capa)
{
  vmcall_frame_t frame;
  if (capa == NULL) {
    goto fail;
  }
  frame.vmcall = TYCHE_ENUMERATE;
  frame.arg_1 = idx;
  if (tyche_call(&frame) != 0) {
    goto fail;
  }
  // Setup the capability with the values in the registers.
  capa->local_id = frame.value_1; 
  capa->capa_type = ((frame.value_2 & Revocation) != 0)? Revocation : Resource;
  capa->resource_type = (frame.value_2 & ~(Revocation));
  capa->last_read_ref_count = frame.value_6;

  // Parse the information encoded from AccessRights.as_bits().
  switch(capa->resource_type) {
    case Domain:
      capa->access.domain.status = frame.value_3;
      switch(capa->access.domain.status) {
        case None:
          goto fail;
          break;
        case Unsealed:
        case Sealed:
          capa->access.domain.info.capas.spawn = frame.value_4;
          capa->access.domain.info.capas.comm = frame.value_5;
          break;
        case Channel:
          //TODO should have info about the domain id.
          break;
        case Transition:
          capa->access.domain.info.transition = frame.value_4;
          break;
        default:
          goto fail;
      } 
      break;
    case Region:
      capa->access.region.start = frame.value_3;
      capa->access.region.end = frame.value_4;
      capa->access.region.flags = frame.value_5;
      break;
    case CPU:
      capa->access.cpu.flags = frame.value_5; 
      break;
    default:
      goto fail;
  }
  // Everything went well.
  return 0; 
fail:
  return -1;
}
