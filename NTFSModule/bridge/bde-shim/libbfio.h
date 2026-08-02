/* Minimal shim so libbde.h (LIBBDE_HAVE_BFIO) compiles without the full
 * bundled libbfio public header. Only the opaque handle type is needed;
 * libbfio symbols resolve from libbde.a at link time. */
#ifndef NK_LIBBFIO_SHIM_H
#define NK_LIBBFIO_SHIM_H
#include <stdint.h>
#include <sys/types.h>
typedef struct libbfio_handle libbfio_handle_t;
typedef struct libbfio_pool libbfio_pool_t;
#endif
