#ifndef __INCLUDE_ENCLAVE_APP_H__
#define __INCLUDE_ENCLAVE_APP_H__

/// Configuration for the enclave.
/// This allows to select which example to run via shared memory.
typedef struct {
  /// arguments for this application.
  void* args;
} config_t;

typedef unsigned long long nonce_t;
typedef unsigned long long phys_offset_t;
typedef unsigned long long hash_part_t;
#define PUB_KEY_SIZE 32
#define SIGNED_DATA_SIZE 64
/// Hello world argument.
typedef struct {
  char reply[30];
  nonce_t nonce;
  char pub_key[PUB_KEY_SIZE];
  char signed_enclave_data[SIGNED_DATA_SIZE];
  // nonce_t nonce_resp;
  // hash_part_t hash_low_low;
  // hash_part_t hash_low_high;
  // hash_part_t hash_high_low;
  // hash_part_t hash_high_high;
} hello_world_t;



#endif
