/* Force the linker to look for some symbols.                              */
EXTERN(__manifest)

SECTIONS
{
  /* Start address */
  . = 0x80000000000;

  /* Output a text section */
  .text : ALIGN(0x1000) {
    *(.text)
    *(.text.*)
  }

  /* Output the rodata */
  .rodata : ALIGN(0x1000) {
    KEEP(*(__*))
    *(.rodata)
    *(.rodata.*)
  }

  /* Finally, all data                                         */
  /* NOTE: no need to page-align bss, both bss and data are RW */
  .data : ALIGN(0x1000) {
    KEEP(*(__manifest))
    *(.data)
    *(.data.*)
  }
  .bss : {
    *(.bss)
    *(.bss.*)
  }
}
