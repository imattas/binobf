    .text

#ifdef _WIN32
#define FUNCTION(name) \
    .def name; .scl 2; .type 32; .endef; \
    .globl name; \
    .p2align 2; \
name:
#define END_FUNCTION(name)
#else
#define FUNCTION(name) \
    .type name,@function; \
    .globl name; \
    .p2align 2; \
name:
#define END_FUNCTION(name) .size name, .-name
#endif

FUNCTION(binobf_arm64_transform_exact)
    mov x9, x0
    mov x10, #0
    cmp x0, #0
    b.eq .Lexact_true
    b .Lexact_false
.Lexact_true:
    nop
    nop
    add x0, x9, #1
    ret
.Lexact_false:
    add x0, x9, #2
    ret
END_FUNCTION(binobf_arm64_transform_exact)

FUNCTION(binobf_arm64_transform_blocks)
    b .Lblocks_second
.Lblocks_first:
    add x0, x0, #2
    b .Lblocks_exit
.Lblocks_second:
    add x0, x0, #40
    b .Lblocks_third
.Lblocks_third:
    add x0, x0, #1
    b .Lblocks_first
.Lblocks_exit:
    ret
END_FUNCTION(binobf_arm64_transform_blocks)

FUNCTION(binobf_arm64_transform_secondary)
    add x0, x0, #7
    ret
END_FUNCTION(binobf_arm64_transform_secondary)
