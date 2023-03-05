/**
 * Karel Chanivecky 2023.
 */



#ifndef SOURCES_MEM_H
#define SOURCES_MEM_H

#include <stdint.h>

#include "ciphrameworklib.h"


struct cplib_mem_chunk_t;


typedef int (*cplib_independent_mutator_f)(void *self);

struct cplib_destroyable_t {
    cplib_independent_mutator_f destroy;
};

typedef struct cplib_destroyable_t cplib_destroyable_t;

typedef int (*cplib_mem_chunk_recycle_f)(struct cplib_mem_chunk_t *self, void *data, size_t size, size_t taken);

struct cplib_mem_chunk_t {
    cplib_destroyable_t;
    void *mem;
    size_t size;
    size_t taken;
    cplib_mem_chunk_recycle_f recycle;
};

typedef struct cplib_mem_chunk_t cplib_mem_chunk_t;

cplib_mem_chunk_t *cplib_mem_chunk_new(void *data, size_t size);

cplib_mem_chunk_t *cplib_allocate_mem_chunk_new(size_t size);


int cplib_destroy_chunk(cplib_mem_chunk_t *chunk);


typedef int (*cplib_mem_chunk_func)(void *self, cplib_mem_chunk_t *data);

/**
 * Get the next item. If passed NULL will allocate a new item. Else, will recycle the item.
 */
typedef int (*cplib_next_item_f)(void *self, void **item);

#define CPLIB_DESTROY_CHUNK(chunk) (chunk)->destroy((chunk)), (chunk) = NULL
#define CPLIB_DESTROY_CHUNK_IF_IS_NOT(chunk, other)     \
    if ((chunk) != (other))                             \
        (CPLIB_DESTROY_CHUNK(chunk));                   \
    else                                                \
        (chunk) = NULL

#endif //SOURCES_MEM_H
