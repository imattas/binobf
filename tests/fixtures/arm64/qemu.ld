ENTRY(_start)

SECTIONS
{
    . = 0x40000000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    . = ALIGN(16);
    . += 0x10000;
    __stack_top = .;
    /DISCARD/ : { *(.comment*) *(.note*) }
}
