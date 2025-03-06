#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "common.h"
#include "common_log.h"
#include "seal_app.h"
#include "sdk_tyche.h"
#include "sdk_tyche_rt.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <time.h>
#include <ucontext.h>
#include <pthread.h>
#include <sched.h>

// ———————————————————————————— Local Variables ————————————————————————————— //

tyche_domain_t *enclave = NULL;

unsigned int NET_PORT = 1234;

// ———————————————————————— Declare the RB functions ———————————————————————— //

RB_DECLARE_FUNCS(char);

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct seal_args_t {
  /// The core for the seal thread.
  usize core;
  /// The args.
  seal_app_t* app;
} seal_args_t;

// ———————————————————————————————— Helpers ————————————————————————————————— //

/// Looks up for the shared memory region with the enclave.
static void *find_default_shared(tyche_domain_t *enclave) {
  domain_shared_memory_t *shared_sec = NULL;
  if (enclave == NULL) {
    ERROR("Supplied enclave is null.");
    goto failure;
  }
  // Find the shared region.
  dll_foreach(&(enclave->shared_regions), shared_sec, list) {
    if (shared_sec->segment->p_type == KERNEL_SHARED) {
      return (void *)(shared_sec->untrusted_vaddr);
    }
  }
  ERROR("Unable to find the shared buffer for the enclave!");
failure:
  return NULL;
}

int pin_self_to_core(usize core) {
  pthread_t thread = pthread_self();
  cpu_set_t affinity_mask;
  CPU_ZERO(&affinity_mask);
  CPU_SET(core, &affinity_mask);
  if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &affinity_mask) != 0) {
    ERROR("Unable to set thread affinity on core %lld", core);
    return FAILURE;
  }
  return SUCCESS;
}

#ifdef RUN_DEBUG_SEAL

void* run_seal(void* arg) {
  seal_args_t* seal_arg = (seal_args_t*) arg;
  int read = 0;
  int written = 0;
  char buffer[MSG_BUFFER_SIZE] = {0};
  if (pin_self_to_core((seal_arg->core)) != SUCCESS) {
      ERROR("Pinning in seal thread did not work.");
      goto failure;
  }
  // main loop, read on a channel, write on the other.
  while(1) {
    // Start by reading.
    while((read = rb_char_read_n(&(seal_arg->app->to_seal),
            MSG_BUFFER_SIZE, buffer)) == 0) {
      //TODO: if we want to sleep, do it here.
    }
    if (read == FAILURE) {
      ERROR("Reading in run seal returned a failure.");
      goto failure;
    }
    printf("seal_in: %s\n", buffer);
    // Now write.
    written = 0;
    while(written < read) {
      int res = rb_char_write_n(&(seal_arg->app->from_seal), read - written, &buffer[written]);
      if (res == FAILURE) {
        ERROR("Failed to write to the from channel");
        goto failure;
      }
      written += res;
    }
    read = 0;
  }

  LOG("Done running seal!");
  return NULL;
failure:
  return NULL;
}

#else
// Thread running seal.
void* run_seal(void* arg) {
  seal_args_t* seal_arg = (seal_args_t*) arg;
  if (pin_self_to_core((seal_arg->core)) != SUCCESS) {
      ERROR("Pinning in seal thread did not work.");
      goto failure;
  }
  // For the moment do not run it yet
  if (sdk_call_domain(enclave) != SUCCESS) {
    ERROR("Failure running the seal enclave");
    goto failure;
  }
  LOG("Seal exited!");
  exit(-1);
  return NULL;
failure:
  return NULL;
}
#endif

static usize coremap_to_core(usize coremap) {
  for (usize i = 0; i < 32; i++) {
    if (((1ULL << i) & coremap) != 0) {
        return i;
    }
  }
  ERROR("Unable to find the core index in %llx", coremap);
  exit(-1);
  return 0;
}

// —————————————————————————————————— Main —————————————————————————————————— //
int main(int argc, char *argv[]) {
  // Thread to run seal.
  pthread_t seal_thread;
  // Number of cores.
  usize core_count = sdk_get_core_count();
  // The mask of runable cores.
  usize core_mask = sdk_all_cores_mask();
  // The core for seal.
  usize seal_coremap = (core_count > 1)? (1UL << 1) : (1UL << 0);
  // The output core
  usize output_core = 0;
  // The datastructure shared with the seal enclave.
  seal_app_t* comm = NULL;
  // Arguments for the seal thread.
  seal_args_t seal_args = {0};

#ifdef RUN_TCP
  if (argc > 1) {
    char *endptr;
    unsigned int arg = strtoul(argv[1], &endptr, 10);
    if (*endptr != '\0') {
        LOG("Invalid input port, default %d is used...", NET_PORT);
    } else {
      NET_PORT = arg;
      LOG("PORT changed to %d", NET_PORT);
    }
  } else {
    LOG("No port provided, using the default %d", NET_PORT);
  }
#endif

  // Pin ourselves to the core 0.
  if (pin_self_to_core(0) != SUCCESS) {
    goto failure;
  } 

  // Avoid running thread benchmarks with sdktyche that does not have interrupts.
#if !defined(RUN_WITH_KVM) || RUN_WITH_KVM == 0
  if (core_count <= 1) {
    ERROR("The # of cores (%lld) must be > 1 for tyche sdk", core_count);
    goto failure;
  } 
#endif

  // Allocate the enclave.
  enclave = malloc(sizeof(tyche_domain_t));
  if (enclave == NULL) {
    ERROR("Unable to allocate enclave structure");
    goto failure;
  }
  // Init the seal enclave.
  if (sdk_create_domain(enclave, argv[0], seal_coremap, 0, DEFAULT_PERM) !=
      SUCCESS) {
    ERROR("Unable to parse the enclave");
    goto failure;
  }

  // Initialize the communication channels.
  comm = (seal_app_t*) find_default_shared(enclave);
  if (comm == NULL) {
    ERROR("Unable to find the default shared region.");
    goto failure;
  }
  // Initialize the channels.
  if (rb_char_init(&(comm->to_seal), MSG_BUFFER_SIZE, comm->to_buffer) != SUCCESS) {
    ERROR("Problem in the init of the to_seal channel.");
    goto failure;
  }
  if (rb_char_init(&(comm->from_seal), MSG_BUFFER_SIZE, comm->from_buffer) != SUCCESS) {
    ERROR("Problem in the init of from seal channel.");
    goto failure;
  }
  memset(comm->to_buffer, 0, sizeof(char) * MSG_BUFFER_SIZE);
  memset(comm->from_buffer, 0, sizeof(char) * MSG_BUFFER_SIZE);
  
  // Run the thread for seal.
  seal_args.core = coremap_to_core(seal_coremap);
  seal_args.app = comm;
  if (pthread_create(&seal_thread, NULL, run_seal, (void*) &seal_args) < 0) {
    ERROR("Failed to create the seal thread");
    goto failure;
  }

#ifdef RUN_TCP
  // run the tcp server.
  if (tcp_start_server(output_core, comm) != SUCCESS) {
    ERROR("TCP server failed.");
    goto failure;
  }
#else
  // By default we run the stdin version.
  if (stdin_start_server(output_core, comm) != SUCCESS) {
    ERROR("Stdin server failed.");
    goto failure;
  }
#endif

  // Join the threads.
  pthread_join(seal_thread, NULL);

  // Delete the enclave.
  if (sdk_delete_domain(enclave) != SUCCESS) {
    ERROR("Unable to delete the seal domain.");
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}
