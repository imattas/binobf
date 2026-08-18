    .text
    .code32

#ifdef _WIN32
#define BINOBF_FUNCTION(name) \
    .def name; .scl 2; .type 32; .endef; \
    .globl name; \
name:
#define BINOBF_END(name)
#else
#define BINOBF_FUNCTION(name) \
    .globl name; \
    .type name,@function; \
name:; \
    .cfi_startproc
#define BINOBF_END(name) \
    .cfi_endproc; \
    .size name, .-name
#endif

BINOBF_FUNCTION(binobf_x86_corpus_pattern)
    movl $42, %eax
    nop
    .byte 0x0f, 0x1f, 0x00
    .byte 0x0f, 0x1f, 0x00
    xorl %ecx, %ecx
    testl %ecx, %ecx
    je .Lcorpus_true
    jmp .Lcorpus_false
.Lcorpus_true:
    movl $42, %eax
    ret
.Lcorpus_false:
    movl $41, %eax
    ret
BINOBF_END(binobf_x86_corpus_pattern)

BINOBF_FUNCTION(binobf_x86_corpus_blocks)
    xorl %eax, %eax
    jmp .Lcorpus_second
.Lcorpus_first:
    addl $2, %eax
    jmp .Lcorpus_exit
.Lcorpus_second:
    addl $40, %eax
    jmp .Lcorpus_first
.Lcorpus_exit:
    ret
BINOBF_END(binobf_x86_corpus_blocks)

BINOBF_FUNCTION(binobf_x86_corpus_secondary)
    movl $7, %eax
    ret
BINOBF_END(binobf_x86_corpus_secondary)

BINOBF_FUNCTION(binobf_x86_corpus_consumer)
#ifdef _WIN32
    calll _binobf_c_add
#else
    calll binobf_c_add@PLT
#endif
    ret
BINOBF_END(binobf_x86_corpus_consumer)

#ifdef _WIN32
    .data
    .p2align 2
    .globl __tls_index
__tls_index:
    .long 0
    .globl __tls_array
__tls_array:
    .long 0
    .globl __fltused
__fltused:
    .long 0
#endif
