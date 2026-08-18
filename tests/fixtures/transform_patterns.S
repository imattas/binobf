    .text

#ifdef _WIN32
    .def binobf_transform_pattern;
    .scl 2;
    .type 32;
    .endef
#else
    .type binobf_transform_pattern,@function
#endif
    .globl binobf_transform_pattern
    .p2align 4, 0x90
binobf_transform_pattern:
#ifndef _WIN32
    .cfi_startproc
#endif
    movabsq $42, %r10
    .byte 0x0f, 0x1f, 0x00
    .byte 0x0f, 0x1f, 0x00
    xorl %eax, %eax
    testl %eax, %eax
    je .Lpattern_true
    jmp .Lpattern_false
.Lpattern_true:
    movl $42, %eax
    retq
.Lpattern_false:
    movl $41, %eax
    retq
#ifndef _WIN32
    .cfi_endproc
    .size binobf_transform_pattern, .-binobf_transform_pattern
#endif

#ifdef _WIN32
    .def binobf_transform_blocks;
    .scl 2;
    .type 32;
    .endef
#else
    .type binobf_transform_blocks,@function
#endif
    .globl binobf_transform_blocks
    .p2align 4, 0x90
binobf_transform_blocks:
#ifndef _WIN32
    .cfi_startproc
#endif
    xorl %eax, %eax
    jmp .Lblocks_second
.Lblocks_first:
    addl $2, %eax
    jmp .Lblocks_exit
.Lblocks_second:
    addl $40, %eax
    jmp .Lblocks_first
.Lblocks_exit:
    retq
#ifndef _WIN32
    .cfi_endproc
    .size binobf_transform_blocks, .-binobf_transform_blocks
#endif

#ifdef _WIN32
    .def binobf_transform_secondary;
    .scl 2;
    .type 32;
    .endef
#else
    .type binobf_transform_secondary,@function
#endif
    .globl binobf_transform_secondary
    .p2align 4, 0x90
binobf_transform_secondary:
#ifndef _WIN32
    .cfi_startproc
#endif
    movl $7, %eax
    retq
#ifndef _WIN32
    .cfi_endproc
    .size binobf_transform_secondary, .-binobf_transform_secondary
#endif
