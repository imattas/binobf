.intel_syntax noprefix
.text

#ifdef _WIN32
#define ARG0 ecx
#define ARG1 edx
#define FUNC_META(name) .def name; .scl 2; .type 32; .endef
#define FUNC_END(name)
#else
#define ARG0 edi
#define ARG1 esi
#define FUNC_META(name) .type name,@function
#define FUNC_END(name) .size name, .-name
#endif

.globl binobf_vm_add
FUNC_META(binobf_vm_add)
binobf_vm_add:
    mov eax, ARG0
    add eax, ARG1
    ret
FUNC_END(binobf_vm_add)

.globl binobf_vm_branch
FUNC_META(binobf_vm_branch)
binobf_vm_branch:
    mov eax, ARG0
    cmp ARG0, ARG1
    jl .Lbranch_less
    sub eax, ARG1
    ret
.Lbranch_less:
    add eax, ARG1
    ret
FUNC_END(binobf_vm_branch)

.globl binobf_vm_mix
FUNC_META(binobf_vm_mix)
binobf_vm_mix:
    mov eax, ARG0
    xor eax, 0x5a5a5a5a
    add eax, 7
    imul eax, eax
    ret
FUNC_END(binobf_vm_mix)
