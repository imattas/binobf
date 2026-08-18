    .text
    .p2align 4
    .globl binobf_linked_entry
binobf_linked_entry:
    sub $40, %rsp
    xor %ecx, %ecx
    call *__imp_ExitProcess(%rip)
    int3

    .p2align 4
    .globl binobf_linked_export
binobf_linked_export:
    mov $42, %eax
    ret
