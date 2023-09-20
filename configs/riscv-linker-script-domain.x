OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
  /* Start address */
  . = 0x1000;

  .text : ALIGN(0x1000) {
    *(.text)
    *(.text.*)
  }
  .rodata : ALIGN(0x1000) {
    KEEP(*(__*))
    *(.rodata)
    *(.rodata.*)
  }

  .data : ALIGN(0x1000) {
    KEEP(*(__*))
    *(.data)
    *(.data.*)
  }
  .bss : ALIGN(0x1000) {
    *(.bss)
    *(.bss.*)
  }

  .unmapped : ALIGN(0x1000) {
    *(.*)
  }
}

