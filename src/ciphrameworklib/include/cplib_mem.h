/**
 * Karel Chanivecky 2023.
 */



#ifndef SOURCES_MEM_H
#define SOURCES_MEM_H

#include <stdint.h>

struct cplib_mem_chunk_t;


typedef int (*cplib_independent_mutator_f)(void *self);

struct cplib_destroyable_t {
    cplib_independent_mutator_f destroy;
    int ref_count;
};

typedef struct cplib_destroyable_t cplib_destroyable_t;

typedef int (*cplib_mem_chunk_recycle_f)(struct cplib_mem_chunk_t *self, void *data, size_t taken);

#define CPLIB_MEM_DESTROY 1
#define CPLIB_MEM_KEEP 0

int cplib_destroyable_put(void *destroyable);

int cplib_destroyable_hold(void *destroyable);

cplib_destroyable_t *cplib_destroyable_new(size_t size);

int cplib_destroyable_destroy(struct cplib_destroyable_t *destroyable);

struct cplib_mem_chunk_t {
    cplib_destroyable_t;
    void *mem;
    size_t size;
    size_t taken;
    cplib_mem_chunk_recycle_f recycle;
};

typedef struct cplib_mem_chunk_t cplib_mem_chunk_t;

cplib_mem_chunk_t *cplib_mem_chunk_new(void *data, size_t size);

cplib_mem_chunk_t *cplib_mem_chunk_str_new(char *string);

cplib_mem_chunk_t *cplib_allocate_mem_chunk(size_t size);

int cplib_destroy_chunk(cplib_mem_chunk_t *chunk);


typedef int (*cplib_mem_chunk_func)(void *self, cplib_mem_chunk_t *data);

/**
 * Get the next item. If passed NULL will allocate a new item. Else, will recycle the item.
 */
typedef int (*cplib_next_item_f)(void *self, void **item);

#define CPLIB_PUT_IF_EXISTS(destroyable) if ((destroyable)) cplib_destroyable_put((destroyable)), (destroyable) = NULL
#define CPLIB_HOLD_IF_EXISTS(destroyable) if ((destroyable)) cplib_destroyable_hold((destroyable))

void *cplib_malloc(size_t size);

void cplib_free(void *ptr);

void cplib_hold(void *ptr);


#endif //SOURCES_MEM_H
