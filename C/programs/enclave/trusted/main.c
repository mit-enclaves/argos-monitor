#include "my_shared.h"

const char* message = "Hello World!\n\t";

char encl_stack[0x4000] __attribute__((section(".encl_stack")));

#define NO_CPU_SWITCH (~((unsigned long long)0)) 

void print_message(void* source)
{
  my_encl_message_t* msg = (my_encl_message_t*) source;

  // Handmade memcpy.
  char* ptr = msg->reply;
  char* src = (char*) msg->message;
  for (int i = 0; i < msg->message_len; i++) {
    ptr[i] = src[i];
  } 
}

// Puts hello world inside the shared dest buffer.
void trusted_entry(unsigned long long ret_handle, void* args)
{
  print_message(args);
  // Use the return handle.
  asm(
    "movq $9, %%rax\n\t"
    "movq %0, %%rdi\n\t"
    "movq %1, %%rsi\n\t"
    "vmcall"
    :
    : "rm" (ret_handle), "rm" (NO_CPU_SWITCH)
    : "rax", "rdi", "memory");
}

int fibonnacci(int n)
{
  if (n <= 0) {
    return 0;
  } else if (n == 1) {
    return 1;
  }
  return (fibonnacci(n-1) + fibonnacci(n-2));
}

void fibonnacci_out()
{
  fibonnacci(10);
}

// Just to look good.
int _start() {
    /* exit system call */
    asm("movl $1,%eax;"
        "xorl %ebx,%ebx;"
        "int  $0x80"
    );
}
