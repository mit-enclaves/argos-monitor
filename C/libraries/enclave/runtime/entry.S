
/// Trap Frame Format

/// arguments
#define RDI	(0)
#define RSI	(8)
#define RDX	(16)
#define RCX	(24)
#define R8	(32)
#define R9	(40)

/// other registers
#define R10	(48)
#define R11	(56)
#define RBX	(64)
#define RBP	(72)
#define R12	(80)
#define R13	(88)
#define R14	(96)
#define R15	(104)
#define RAX	(112)
#define REG_END (120)

#define TRANSITION $0x999

.text

  /// macro to save destructable register state
	.macro SAVE_REGS
	movq	%rdi, RDI(%rsp)
	movq	%rsi, RSI(%rsp)
	movq	%rdx, RDX(%rsp)
	movq	%rcx, RCX(%rsp)
	movq	%r8, R8(%rsp)
	movq	%r9, R9(%rsp)
	movq	%r10, R10(%rsp)
	movq	%r11, R11(%rsp)
  movq  %r12, R12(%rsp)
  movq  %r13, R13(%rsp)
  movq  %r14, R14(%rsp)
  movq  %r15, R15(%rsp)
	movq	%rax, RAX(%rsp)
	.endm

  /// macro to restore destructible register state.
	.macro RESTORE_REGS
	movq	RAX(%rsp), %rax
  movq  R15(%rsp), %r15
  movq  R14(%rsp), %r14
  movq  R13(%rsp), %r13
  movq  R12(%rsp), %r12
  movq  R11(%rsp), %r11
	movq	R10(%rsp), %r10
	movq	R9(%rsp), %r9
	movq	R8(%rsp), %r8
  movq  RCX(%rsp), %rcx
	movq	RDX(%rsp), %rdx
	movq	RSI(%rsp), %rsi
	movq	RDI(%rsp), %rdi
	.endm

/// void domain_gate_vmcall(uint64_t target_domain, void (*function) (void*), void* args); 
/// Argument order: rdi, rsi, rdx, rcx, r8, r9.
/// The API for tyche is rcx, rdx, rsi.
/// Vmfunc should be very similar (replace the vmcall with vmfunc)
.globl domain_gate_vmcall
domain_gate_vmcall:
  // vmcall expects rdi to be the target domain.
  // It replaces it with the caller when we are the target.
  movq %rdi, %rcx  
  movq TRANSITION, %rax
  vmcall

  movq $0x500, %rax
  movq $0xbadbabe, %rcx
  vmcall

  // We are in the callee.
  // rdi should now contain where we should return.
  #subq REG_END, %rsp
  #SAVE_REGS

  // Move the args.
  movq  %rdx, %rdi
  
  // Call the target function.
  callq *%rsi

  RESTORE_REGS
  movq %rdi, %rax
  vmcall
  
  //We are back in the caller.
  // rdi should be replaced by the callee now.
  retq
