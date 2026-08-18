#ifndef BINOBF_C_API_H
#define BINOBF_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(BINOBF_C_API_BUILD)
#    define BINOBF_C_API __declspec(dllexport)
#else
#    define BINOBF_C_API
#endif

/* Stable C ABI revision for this header. */
#define BINOBF_C_API_VERSION 1u

typedef enum binobf_status {
    BINOBF_STATUS_OK = 0,
    BINOBF_STATUS_INVALID_ARGUMENT = 1,
    BINOBF_STATUS_FAILURE = 2,
} binobf_status;

typedef struct binobf_error {
    uint32_t struct_size;
    char* code;
    size_t code_capacity;
    char* message;
    size_t message_capacity;
} binobf_error;

typedef struct binobf_detection {
    uint32_t struct_size;
    uint32_t format;
    uint32_t type;
    uint32_t architecture;
    uint64_t entry_point;
} binobf_detection;

/* Returns the semantic binobf project version compiled into the library. */
BINOBF_C_API const char* binobf_version(void);

/*
 * Detects a binary without taking ownership of input or output memory.
 * All output structs must be zero-initialized and have struct_size set to
 * sizeof(their type). Error strings are copied into caller-owned buffers and
 * are always NUL-terminated when capacity is nonzero.
 */
BINOBF_C_API binobf_status binobf_detect(
    const void* bytes,
    size_t size,
    const char* source_name,
    binobf_detection* output,
    binobf_error* error);

#ifdef __cplusplus
}
#endif

#undef BINOBF_C_API

#endif
