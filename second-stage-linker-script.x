/* Force the linker to look for some symbols.                              */
/* In our case those symbols all start with '__', and are copied in their */
/* respective sections with `KEEP(*(__*))`*/
EXTERN(__manifest __statics __pages __current_domain)

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
    KEEP(*(__*))
    *(.data)
    *(.data.*)
  }
  .bss : {
    *(.bss)
    *(.bss.*)
  }
}
