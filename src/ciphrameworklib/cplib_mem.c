/**
 * Karel Chanivecky 2023.
 */
#include <stdlib.h>
#include <string.h>

#include "cplib_mem.h"
#include "cplib_log.h"
#include "ciphrameworklib.h"

int cplib_mem_chunk_recycle(struct cplib_mem_chunk_t *self, void *data, size_t taken) {
    if (self->size < taken) {
        LOG_DEBUG("Trying to recycle a chunk that is too small (%zu < %zu)\n", self->size, taken);
        return CPLIB_ERR_DATA_SIZE;
    }

    memcpy(self->mem, data, taken);
    self->taken = taken;
    return CPLIB_ERR_SUCCESS;
}


int cplib_destroy_chunk(cplib_mem_chunk_t *chunk) {
    cplib_free(chunk->mem);
    chunk->mem = NULL;
    chunk->size = 0;
    chunk->taken = 0;
    chunk->destroy = NULL;
    chunk->recycle = NULL;
    cplib_free(chunk);
    return CPLIB_ERR_SUCCESS;
}

cplib_mem_chunk_t *cplib_create_chunk(size_t size) {
    cplib_mem_chunk_t *chunk = (cplib_mem_chunk_t *) cplib_destroyable_new(size);
    if (!chunk) {
        LOG_DEBUG("Cannot allocate chunk of split_size %zu. Out of memory\n", size);
        return NULL;
    }

    chunk->size = size;
    chunk->taken = 0;
    chunk->recycle = cplib_mem_chunk_recycle;
    chunk->destroy = (cplib_independent_mutator_f) cplib_destroy_chunk;
    return chunk;
}

struct cplib_mem_chunk_t *cplib_allocate_mem_chunk(size_t size) {
    cplib_mem_chunk_t *chunk = cplib_create_chunk(size);
    if (!chunk) {
        return NULL;
    }

    chunk->mem = (void *) cplib_malloc(size);

    if (!chunk->mem) {
        LOG_DEBUG("Cannot allocate chunk of split_size %zu. Out of memory\n", size);
        cplib_free(chunk);
        return NULL;
    }

    return chunk;
}

cplib_mem_chunk_t *cplib_mem_chunk_new(void *data, size_t size) {
    cplib_mem_chunk_t *chunk = cplib_create_chunk(size);
    if (!chunk) {
        return NULL;
    }
    chunk->mem = cplib_malloc(size);
    if (!chunk->mem) {
        cplib_destroyable_put(chunk);
        return NULL;
    }

    memcpy(chunk->mem, data, size);
    chunk->taken = size;

    return chunk;
}

#define REF_COUNT_SIZE sizeof(uint64_t)

void *cplib_malloc(size_t size) {
    uint64_t *mem;

    mem = (uint64_t *) malloc(size + REF_COUNT_SIZE);
    if (!mem) {
        return NULL;
    }

    LOG_VERBOSE("Allocated: %p\n", (void *) mem);

    memset(mem, 0, size + REF_COUNT_SIZE);
    mem[0] = 1;

    return &mem[1];
}

void cplib_free(void *ptr) {
    if (!ptr) {
        LOG_VERBOSE("Freeing NULL\n");
        return;
    }
    uint64_t *mem;
    uint64_t ref_count;

    mem = (uint64_t *) ptr - REF_COUNT_SIZE;
    mem[0]--;
    ref_count = mem[0];

    LOG_VERBOSE("Put: %p\n", (void *) mem);

    if (ref_count == 0) {
        free(mem);
        LOG_VERBOSE("Freeing: %p\n", (void *) mem);
    }
}

void cplib_hold(void *ptr) {
    uint64_t *mem;

    mem = (uint64_t *) ptr - REF_COUNT_SIZE;
    mem[0]++;

    LOG_VERBOSE("Hold: %p\n", (void *) mem);
}

int cplib_destroyable_destroy(cplib_destroyable_t *destroyable) {
    destroyable->ref_count = 0;
    cplib_free(destroyable);
    return CPLIB_ERR_SUCCESS;
}

int cplib_destroyable_put(void *destroyable_ptr) {
    int ret;
    cplib_destroyable_t *destroyable = (cplib_destroyable_t *) destroyable_ptr;
    destroyable->ref_count--;
    LOG_VERBOSE("Destroyable put: %p\n", destroyable);

    if (destroyable->ref_count == 0) {
        LOG_VERBOSE("Destroyable reached ref_count == 0: %p\n", destroyable);
        if (!destroyable->destroy || destroyable->destroy == (cplib_independent_mutator_f) cplib_destroyable_put) {
            cplib_destroyable_destroy(destroyable);
            return CPLIB_MEM_DESTROY;
        }

        ret = destroyable->destroy(destroyable);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_VERBOSE("Failed to destroy: %p\n", destroyable);
        };

        return CPLIB_MEM_DESTROY;
    }

    return CPLIB_MEM_KEEP;
}

int cplib_destroyable_hold(void *destroyable_ptr) {
    cplib_destroyable_t *destroyable = (cplib_destroyable_t *) destroyable_ptr;
    LOG_VERBOSE("Destroyable hold: %p\n", destroyable);
    destroyable->ref_count++;
    return CPLIB_ERR_SUCCESS;
}


cplib_destroyable_t *cplib_destroyable_new(size_t size) {
    cplib_destroyable_t *destroyable = (cplib_destroyable_t *) cplib_malloc(size);
    destroyable->ref_count = 1;
    destroyable->destroy = (cplib_independent_mutator_f) cplib_destroyable_put;
    return destroyable;
}
