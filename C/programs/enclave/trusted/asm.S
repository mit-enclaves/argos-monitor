.text

.globl encl_start
encl_start:
  movq %rcx, %rdi
  movq %r10, %rsi
  callq trusted_entry
  callq fibonnacci_out 
  movq $0x500, %rax
  movq $0xbedb0b, %rcx
  vmcall
