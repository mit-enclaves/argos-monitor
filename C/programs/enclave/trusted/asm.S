.text

.globl encl_start
encl_start:
  movq %r11, %rsi
  callq trusted_entry
  callq fibonnacci_out 
  movq $0x500, %rax
  movq $0xbedb0b, %rcx
  vmcall
