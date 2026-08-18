    .text
    .p2align 4
    .globl binobf_linked_entry
binobf_linked_entry:
    xor %eax, %eax
    ret

    .p2align 4
    .globl binobf_linked_export
binobf_linked_export:
    mov $42, %eax
    ret
