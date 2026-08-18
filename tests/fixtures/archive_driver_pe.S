    .text
    .globl archive_entry
archive_entry:
    subq $40, %rsp
    movl $20, %ecx
    movl $1, %edx
    callq archive_add
    movl %eax, %ecx
    callq archive_double
    movl %eax, %ecx
    callq ExitProcess
    int3
