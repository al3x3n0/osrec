ENTRY(_start)
SECTIONS {
  . = 0x41000000;
  .text : { KEEP(*(.text.boot)) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  . = ALIGN(16384);
  __bss_start = .;
  .bss : { *(.bss*) *(COMMON) }
  __bss_end = .;
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) }
}
