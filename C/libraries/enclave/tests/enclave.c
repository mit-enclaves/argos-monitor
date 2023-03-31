char encl_stack[0x4000] __attribute__((section(".encl_stack")));


// Puts hello world inside the shared dest buffer.
void trusted_entry(void* dest)
{
  char* message = "Hello world!\n\0";
  // Handmade memcpy.
  char* ptr = (char*) dest;
  for (int i = 0; i < 14; i++) {
    ptr[i] = message[i];
  } 
}

// Just to look good.
int _start() {
    /* exit system call */
    asm("movl $1,%eax;"
        "xorl %ebx,%ebx;"
        "int  $0x80"
    );
}
