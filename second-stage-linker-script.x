/* Forces the linker to look for the manifest symbol */
EXTERN(__second_stage_manifest)

SECTIONS
{
  /* Start address */
  . = 0x8000000;

  /* Output a text section */
  .text : ALIGN(0x1000) {
    *(.text)
    *(.text.*)
  }

  /* Output the rodata */
  .rodata : ALIGN(0x1000) {
    KEEP(*(.rodata.__second_stage_manifest)) /* Marks symbol as used, to prevent GC*/
    *(.rodata)
    *(.rodata.*)
  }

  /* Finally, all data                                         */
  /* NOTE: no need to page-align bss, both bss and data are RW */
  .data : ALIGN(0x1000) {
    *(.data)
    *(.data.*)
  }
  .bss : {
    *(.bss)
    *(.bss.*)
  }
}
