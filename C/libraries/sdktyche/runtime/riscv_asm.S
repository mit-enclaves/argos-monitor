.text

// Take a capa_index_t* and a void**, expected to be in rdi, rsi.
.globl riscv_asm_call_gate
riscv_asm_call_gate:
    /*addi sp, sp, -34*8
    sd ra, 0*8(sp)
    sd a0, 1*8(sp)
    sd a1, 2*8(sp)
    sd a2, 3*8(sp)
    sd a3, 4*8(sp)
    sd a4, 5*8(sp)
    sd a5, 6*8(sp)
    sd a6, 7*8(sp)
    sd a7, 8*8(sp)
    sd t0, 9*8(sp)
    sd t1, 10*8(sp)
    sd t2, 11*8(sp)
    sd t3, 12*8(sp)
    sd t4, 13*8(sp)
    sd t5, 14*8(sp)
    sd t6, 15*8(sp)
    sd zero, 16*8(sp)
    sd gp, 17*8(sp)
    sd tp, 18*8(sp)
    sd s0, 19*8(sp)
    sd s1, 20*8(sp)
    sd s2, 21*8(sp)
    sd s3, 22*8(sp)
    sd s4, 23*8(sp)
    sd s5, 24*8(sp)
    sd s6, 25*8(sp)
    sd s7, 26*8(sp)
    sd s8, 27*8(sp)
    sd s9, 28*8(sp)
    sd s10, 29*8(sp)
    sd s11, 30*8(sp) */
    ld a2, 0x0(a1)      //loading the args - TODO: Make sure this is correct!! Because the tyche call id is supposed to be in a0. 
    ld a1, 0x0(a0)
    li a0, 0x9  
    li a7, 0x78ac5b
    ecall 
    //ld t0, 0x1(x0) 
    /* ld ra, 0*8(sp)
    ld a0, 1*8(sp)
    ld a1, 2*8(sp)
    ld a2, 3*8(sp)
    ld a3, 4*8(sp)
    ld a4, 5*8(sp)
    ld a5, 6*8(sp)
    ld a6, 7*8(sp)
    ld a7, 8*8(sp)
    ld t0, 9*8(sp)
    ld t1, 10*8(sp)
    ld t2, 11*8(sp)
    ld t3, 12*8(sp)
    ld t4, 13*8(sp)
    ld t5, 14*8(sp)
    ld t6, 15*8(sp)
    ld zero, 16*8(sp)
    ld gp, 17*8(sp)
    ld tp, 18*8(sp)
    ld s0, 19*8(sp)
    ld s1, 20*8(sp)
    ld s2, 21*8(sp)
    ld s3, 22*8(sp)
    ld s4, 23*8(sp)
    ld s5, 24*8(sp)
    ld s6, 25*8(sp)
    ld s7, 26*8(sp)
    ld s8, 27*8(sp)
    ld s9, 28*8(sp)
    ld s10, 29*8(sp)
    ld s11, 30*8(sp)
    addi sp, sp, 34*8 */
    sret 

.globl _start
_start:
  mv a2, a3
  j trusted_main
  // Should never return here, call exit if we do.
  li a0, 0x1
  li a7, 0x78ac5b
  ecall 
  //ld t0, 0x1(x0)
