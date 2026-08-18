    .text
    .p2align 4
    .globl _start
    .type _start,@function
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
    .size _start, .-_start

    .p2align 4
    .globl binobf_linked_export
    .type binobf_linked_export,@function
binobf_linked_export:
    mov $42, %eax
    ret
    .size binobf_linked_export, .-binobf_linked_export

    .section .note.GNU-stack,"",@progbits
