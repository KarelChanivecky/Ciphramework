/**
 * Karel Chanivecky 2023.
 */
#include <stdlib.h>
#include <string.h>

#include "mem_chunk.h"
#include "log.h"


int cplib_mem_chunk_recycle(struct cplib_mem_chunk_t *self, void *data, size_t size, size_t taken) {
    if (self->size < taken) {
        LOG_DEBUG("Trying to recycle a chunk that is too small (%zu < %zu)\n", self->size, size);
        return CPLIB_ERR_DATA_SIZE;
    }

    memcpy(self->mem, data, size);
    self->taken = size;
    return CPLIB_ERR_SUCCESS;
}


int cplib_destroy_chunk(cplib_mem_chunk_t *chunk) {
    free(chunk->mem);
    chunk->mem = NULL;
    chunk->size = 0;
    chunk->taken = 0;
    chunk->destroy = NULL;
    chunk->recycle = NULL;
    free(chunk);
    return CPLIB_ERR_SUCCESS;
}

cplib_mem_chunk_t *cplib_create_chunk(size_t size) {
    cplib_mem_chunk_t *chunk = (cplib_mem_chunk_t *) malloc(size);
    if (!chunk) {
        LOG_DEBUG("Cannot allocate chunk of size %zu. Out of memory", size);
        return NULL;
    }

    chunk->size = size;
    chunk->taken = 0;
    chunk->recycle = cplib_mem_chunk_recycle;
    chunk->destroy = (cplib_independent_mutator_f) cplib_destroy_chunk;
    return chunk;
}

cplib_mem_chunk_t *cplib_allocate_mem_chunk_new(size_t size) {
    cplib_mem_chunk_t *chunk = cplib_create_chunk(size);
    if (!chunk) {
        return NULL;
    }

    chunk->mem = (void *) malloc(size);

    if (!chunk->mem) {
        LOG_DEBUG("Cannot allocate chunk of size %zu. Out of memory", size);
        free(chunk);
        return NULL;
    }

    return chunk;
}

cplib_mem_chunk_t *cplib_mem_chunk_new(void *data, size_t size) {
    cplib_mem_chunk_t *chunk = cplib_create_chunk(size);
    if (!chunk) {
        return NULL;
    }

    chunk->mem = data;

    return chunk;
}

