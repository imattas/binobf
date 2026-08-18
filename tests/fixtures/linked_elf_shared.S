    .text
    .p2align 4
    .globl binobf_linked_export
    .type binobf_linked_export,@function
binobf_linked_export:
    sub $8, %rsp
    call binobf_external_dependency@PLT
    add $8, %rsp
    ret
    .size binobf_linked_export, .-binobf_linked_export

    .section .note.GNU-stack,"",@progbits
