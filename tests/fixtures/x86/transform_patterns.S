    .text
    .code32

    .comm binobf_x86_common,4,4
#ifdef _WIN32
    .section .tls$B,"dw"
    .globl binobf_x86_tls
binobf_x86_tls:
    .long 0
    .section .data$owned,"dw",discard,binobf_x86_owned_data
    .globl binobf_x86_owned_data
binobf_x86_owned_data:
    .long 7
#else
    .section .tbss,"awT",@nobits
    .globl binobf_x86_tls
    .type binobf_x86_tls,@tls_object
    .size binobf_x86_tls,4
binobf_x86_tls:
    .zero 4
    .section .data.binobf_x86_owned,"awG",@progbits,binobf_x86_owned_data,comdat
    .globl binobf_x86_owned_data
binobf_x86_owned_data:
    .long 7
#endif
    .text

#ifdef _WIN32
    .def binobf_x86_transform_pattern;
    .scl 2;
    .type 32;
    .endef
#else
    .type binobf_x86_transform_pattern,@function
#endif
    .globl binobf_x86_transform_pattern
    .p2align 4, 0x90
binobf_x86_transform_pattern:
#ifndef _WIN32
    .cfi_startproc
#endif
    movl $42, %eax
    nop
    .byte 0x0f, 0x1f, 0x00
    .byte 0x0f, 0x1f, 0x00
    xorl %ecx, %ecx
    testl %ecx, %ecx
    je .Lx86_true
    jmp .Lx86_false
.Lx86_true:
    movl $42, %eax
    ret
.Lx86_false:
    movl $41, %eax
    ret
#ifndef _WIN32
    .cfi_endproc
    .size binobf_x86_transform_pattern, .-binobf_x86_transform_pattern
#endif

#ifdef _WIN32
    .def binobf_x86_transform_blocks;
    .scl 2;
    .type 32;
    .endef
#else
    .type binobf_x86_transform_blocks,@function
#endif
    .globl binobf_x86_transform_blocks
    .p2align 4, 0x90
binobf_x86_transform_blocks:
#ifndef _WIN32
    .cfi_startproc
#endif
    xorl %eax, %eax
    jmp .Lx86_second
.Lx86_first:
    addl $2, %eax
    jmp .Lx86_exit
.Lx86_second:
    addl $40, %eax
    jmp .Lx86_first
.Lx86_exit:
    ret
#ifndef _WIN32
    .cfi_endproc
    .size binobf_x86_transform_blocks, .-binobf_x86_transform_blocks
#endif

#ifdef _WIN32
    .def binobf_x86_transform_secondary;
    .scl 2;
    .type 32;
    .endef
#else
    .type binobf_x86_transform_secondary,@function
#endif
    .globl binobf_x86_transform_secondary
    .p2align 4, 0x90
binobf_x86_transform_secondary:
#ifndef _WIN32
    .cfi_startproc
#endif
    movl $7, %eax
    movl $binobf_x86_common, %edx
    movl $binobf_x86_tls, %ecx
    ret
#ifndef _WIN32
    .cfi_endproc
    .size binobf_x86_transform_secondary, .-binobf_x86_transform_secondary
#endif
