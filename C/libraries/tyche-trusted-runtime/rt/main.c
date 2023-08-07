#include <stdint.h>

#include "idt.h"
#include "gdt.h"
#include "syscall.h"
#include "segments.h"
#include "sdk_tyche_rt.h"

// Function to read the APIC_BASE MSR
static inline uint64_t read_apic_base_msr() {
    uint32_t edx, eax;

    // The APIC_BASE MSR is 0x1B
    uint32_t msr = 0x1B;

    // Use the rdmsr instruction to read the MSR
    __asm__ volatile("rdmsr"
                     : "=d" (edx), "=a" (eax)
                     : "c" (msr)
                     : );

    return ((uint64_t)edx << 32) | eax;
}

// ———————————————————————— Entry Point into binary ————————————————————————— //
void trusted_entry(frame_t* frame)
{
  if (frame == NULL) {
    return;
  }
  // Save the previous values.
  gdtr_t saved_gdt;
  idtr_t saved_idt;
  uint64_t sys_handler; 
  uint16_t ds, es, ss;
  uint64_t* shared = (uint64_t*) get_default_shared_buffer();
  *shared = 555;

  save_gdt(&saved_gdt);

  *shared = 444;
  //save_segments(&ds, &es, &ss); // TODO still have a problem when restoring.
  save_idt(&saved_idt);

  *shared = 333;
  save_syscall(&sys_handler);

  *shared = 222;

  //Set up the gdt
  gdt_assemble();
   *shared = 111;
  //Set up idt handler.
  idt_init(frame);

  *shared = 1112;
  //Set up syscall handler.
  syscall_init();
  //Mark the end of initialization.
  *shared = 777;

  asm volatile (
      "sti\n\t"
      "mov $0, %%ebx\n\t"
      "div %%ebx\n\t"
      :
      :
      :);
/*  __asm__ volatile(
      "sti\n\t"
      "loop_start: jmp loop_start\n\t"
      :
      :
      :);
*/
  //asm volatile("cli\n\t" : : : );
}

/*
#define SYSCALL_MSR 0x00000174

unsigned long long read_msr(unsigned int msr)
{
    unsigned int low, high;
    asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));
    return ((unsigned long long)high << 32) | low;
}

int main()
{
    unsigned long long syscall_msr_value = read_msr(SYSCALL_MSR);
    printf("SYSCALL MSR value: 0x%llx\n", syscall_msr_value);
    return 0;
}
*/
