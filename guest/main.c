// Tell the compiler incoming stack alignment is not RSP%16==8 or ESP%16==12

const int RO = 0x888;
int bss;

__attribute__((force_align_arg_pointer))
void _start() {
  bss = RO;
  asm("movl $0x666, %eax;"
      "movl $0x777, %ebx;"
      "vmcall");
  __builtin_unreachable();
}
