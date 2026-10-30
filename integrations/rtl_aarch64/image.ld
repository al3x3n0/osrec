ENTRY(_start)
SECTIONS {
  . = 0x40000000;
  .result (NOLOAD) : { KEEP(*(.result)) }
  ASSERT(SIZEOF(.result) == 128, "result ABI must be 128 bytes")
  . = 0x40010000;
  .text : { KEEP(*(.text.boot)) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  . = ALIGN(16);
  .bss (NOLOAD) : {
    __bss_start = .;
    *(.bss*) *(COMMON)
    . = ALIGN(16);
    __bss_end = .;
  }
  /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) }
}
