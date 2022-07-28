// Tell the compiler incoming stack alignment is not RSP%16==8 or ESP%16==12

const int RO = 0x888;
int bss;

__attribute__((force_align_arg_pointer)) void _start() {
  bss = RO;
  for (int i = 0; i < 2; i++) {
    asm("movl $0x888, %eax;"
        "movl $0x777, %ebx;"
        "vmcall");
  }

  asm("movq $0xA0, %rax;"
      "movq %rax, %cr4;");

  asm("movl $0x666, %eax;"
      "movl $0x777, %ebx;"
      "vmcall");
  __builtin_unreachable();
}
