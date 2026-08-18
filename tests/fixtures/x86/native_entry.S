#ifndef _WIN32
#error native_entry.S is a Windows i386 fixture
#endif

    .data
    .p2align 2
binobf_native_result:
    .long 0, 0, 0
binobf_native_written:
    .long 0
binobf_native_path:
    .asciz "binobf-native-result.bin"

    .text
    .code32
    .def _binobf_x86_native_entry;
    .scl 2;
    .type 32;
    .endef
    .globl _binobf_x86_native_entry
_binobf_x86_native_entry:
    calll binobf_x86_transform_pattern
    movl %eax, binobf_native_result
    calll binobf_x86_transform_blocks
    movl %eax, binobf_native_result+4
    calll binobf_x86_transform_secondary
    movl %eax, binobf_native_result+8

    pushl $0
    pushl $0x80
    pushl $2
    pushl $0
    pushl $0
    pushl $0x40000000
    pushl $binobf_native_path
    calll _CreateFileA@28
    cmpl $-1, %eax
    je .Lnative_fail
    movl %eax, %ebx

    pushl $0
    pushl $binobf_native_written
    pushl $12
    pushl $binobf_native_result
    pushl %ebx
    calll _WriteFile@20
    testl %eax, %eax
    je .Lnative_close_fail
    cmpl $12, binobf_native_written
    jne .Lnative_close_fail
    pushl %ebx
    calll _CloseHandle@4
    pushl $37
    calll _ExitProcess@4

.Lnative_close_fail:
    pushl %ebx
    calll _CloseHandle@4
.Lnative_fail:
    pushl $90
    calll _ExitProcess@4
