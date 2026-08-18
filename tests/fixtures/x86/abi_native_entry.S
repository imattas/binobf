#ifndef _WIN32
#error abi_native_entry.S is a Windows i386 fixture
#endif

    .text
    .code32
    .def _binobf_x86_abi_entry;
    .scl 2;
    .type 32;
    .endef
    .globl _binobf_x86_abi_entry
_binobf_x86_abi_entry:
    movl $0x11111111, %edx
    movl $0x22222222, %ecx
    movl $0x33333333, %eax
    calll binobf_abi_adapter
    cmpl $0x1234abcd, %eax
    jne .Lentry_fail
    pushl $0
    movl $0x11111111, %edx
    movl $0x22222222, %ecx
    movl $0x33333333, %eax
    calll binobf_abi_adapter
    addl $4, %esp
    cmpl $0x1234abcd, %eax
    jne .Lentry_fail
    pushl $0
    calll _ExitProcess@4
.Lentry_fail:
    pushl $91
    calll _ExitProcess@4

    .def binobf_abi_target;
    .scl 2;
    .type 32;
    .endef
    .globl binobf_abi_target
binobf_abi_target:
    movl %esp, %eax
    andl $15, %eax
    cmpl $12, %eax
    jne .Ltarget_fail
    cmpl $0x11111111, %ecx
    jne .Ltarget_fail
    cmpl $0x22222222, %edx
    jne .Ltarget_fail
    cmpl $0x33333333, 4(%esp)
    jne .Ltarget_fail
    movl $0x1234abcd, %eax
    retl $4
.Ltarget_fail:
    movl $0xbad0bad0, %eax
    retl $4
