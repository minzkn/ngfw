#ifndef NGFW_TYPES_H
#define NGFW_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define NGFW_VERSION "1.0.0"
#define NGFW_VERSION_MAJOR 1
#define NGFW_VERSION_MINOR 0
#define NGFW_VERSION_PATCH 0

#define NGFW_OK 0
#define NGFW_ERR -1
#define NGFW_ERR_INVALID -2
#define NGFW_ERR_NO_MEM -3
#define NGFW_ERR_NO_RESOURCE -4
#define NGFW_ERR_TIMEOUT -5
#define NGFW_ERR_NOT_SUPPORTED -6
#define NGFW_ERR_NOT_FOUND -7
#define NGFW_ERR_EXISTS -8
#define NGFW_ERR_PERM -9

typedef int32_t ngfw_ret_t;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL ((void*)0)
#endif

#define NGFW_MAX_INTERFACES 16
#define NGFW_MAX_SESSIONS 1048576
#define NGFW_MAX_RULES 65536
#define NGFW_PACKET_SIZE 65536
#define NGFW_BUFFER_SIZE 4096

#endif
