#include "idt.h"
#include <stdint.h>
#include "sdk_tyche_rt.h"

// ———————————————————————————————— Globals ————————————————————————————————— //
__attribute__((aligned(0x10))) 
idt_desc_t idt[IDT_MAX_DESCRIPTORS];

static idtr_t idtr;

extern uint64_t isr_stub_table[];

frame_t* ret_handle = NULL;
// ——————————————————————————————— Functions ———————————————————————————————— //

void save_idt(idtr_t* to_save)
{
    __asm__ __volatile__("sidt %0" : "=m" (*to_save));
}

void restore_idt(idtr_t* to_restore)
{
    __asm__ __volatile__("lidt %0" : : "m" (*to_restore));
}

void idt_set_descriptor(
    uint8_t vector,
    uintptr_t isr,
    uint8_t flags,
    uint8_t ist)
{
  //TODO check the offset.
  idt_desc_t* descriptor = &idt[vector];
  descriptor->isr_low = isr & MASK_ISR_LOW; 
  descriptor->kernel_cs = 0x8; //TODO 
  descriptor->ist = ist; 
  descriptor->attributes = flags;
  descriptor->isr_mid = (isr >> SHIFT_ISR_MID) & MASK_ISR_LOW;
  descriptor->isr_high = (isr >> SHIFT_ISR_HIGH) & MASK_ISR_HIGH;
  descriptor->reserved = 0;
}

void idt_init(frame_t* frame)
{
  ret_handle = frame;
  idtr.base = (uintptr_t)&idt[0]; 
  idtr.limit = (uint16_t) (sizeof(idt_desc_t) * IDT_MAX_DESCRIPTORS -1);
  
  
  for (uint16_t vector = 0; vector < 256; vector++) {
    idt_set_descriptor((uint8_t)vector, (uintptr_t) isr_stub_table[vector], 0x8E, 0); 
  }

  __asm__ volatile("lidt %0" : : "memory"(idtr)); // load the new IDT
  //TODO reenable when we want to have interrupts
  //__asm__ volatile("sti");    
}
 
// ———————————————————————————————— Handlers ———————————————————————————————— //
__attribute__((noreturn))
void exception_handler(int sig) {
  int* shared = (int*) get_default_shared_buffer();
  if (sig == 0) {
    *shared = 666;
  } else {
    *shared = 666;
  //  __asm__ volatile("cli; hlt");
  }
  // Let's not do a return from interrupt.
  gate_call(ret_handle);
}
