#include "sdk_tyche_rt.h"
#include "enclave_app.h"
#include "tyche_api.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;

// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //

const char* message = "Hello World!\n\t\0";
const char* message2 = "Bye Bye! :)!\n\t\0";
const char* message3 = "Done attestation!\n\t\0";

/// Simple generic vmcall implementation.
int tyche_call_enclave(vmcall_frame_t* frame)
{
  usize result = FAILURE;
  asm volatile(
    // Setting arguments.
    "movq %7, %%rax\n\t"
    "movq %8, %%rdi\n\t"
    "movq %9, %%rsi\n\n"
    "movq %10, %%rdx\n\t"
    "movq %11, %%rcx\n\t"
    "movq %12, %%r8\n\t"
    "movq %13, %%r9\n\t"
    "vmcall\n\t"
    // Receiving results.
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%rsi, %2\n\t"
    "movq %%rdx, %3\n\t"
    "movq %%rcx, %4\n\t"
    "movq %%r8,  %5\n\t"
    "movq %%r9,  %6\n\t"
    : "=rm" (result), "=rm" (frame->value_1), "=rm" (frame->value_2), "=rm" (frame->value_3), "=rm" (frame->value_4), "=rm" (frame->value_5), "=rm" (frame->value_6)
    : "rm" (frame->vmcall), "rm" (frame->arg_1), "rm" (frame->arg_2), "rm" (frame->arg_3), "rm" (frame->arg_4), "rm" (frame->arg_5), "rm" (frame->arg_6) 
    : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
  return (int)result;
} 

int tyche_domain_attestation(usize nonce, hello_world_t* ans) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_ENCLAVE_ATTESTATION,
    .arg_1 = nonce,
  };
  if (tyche_call_enclave(&frame) != SUCCESS) {
    goto failure;
  }
  ans->hash_low_low = frame.value_1;
  ans->hash_low_high = frame.value_2;
  ans->hash_high_low = frame.value_3;
  ans->hash_high_high = frame.value_4;
  ans->nonce_resp = frame.value_5;
  return SUCCESS;
failure:
  return FAILURE;
}

void my_memcpy(void* dest, void* src, int size)
{
  char* ptr_dest = (char*) dest;
  char* ptr_src = (char*) src;
  for (int i = 0; i < size; i++) {
    ptr_dest[i] = ptr_src[i];
  }
  ptr_dest[size] = '\0';
}

void print_message(void* input, int size)
{
  hello_world_t* msg = (hello_world_t*) (&(shared->args));
  if (msg == 0) {
    int* ptr = (int*) 0xdeadbeef;
    *ptr = 0xdeadbabe;
  }
  my_memcpy(msg->reply, input, size);
}

void hello_world(frame_t* frame)
{
  hello_world_t* msg = (hello_world_t*) (&(shared->args));
  print_message((void*) message, 15);
  // Do a return.
  gate_call(frame);

  nonce_t nonce = msg->nonce;
  tyche_domain_attestation(nonce, msg);
  print_message((void*)message3, 20);
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(frame_t* frame)
{
  // Error.
  if (frame == NULL) {
    return;
  }
  shared = (config_t*) get_default_shared_buffer();
  hello_world(frame);
}
