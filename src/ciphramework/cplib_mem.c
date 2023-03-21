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


static long long allocated_chunks = 0;

int cplib_destroy_chunk(cplib_mem_chunk_t *chunk) {
    allocated_chunks--;
    LOG_VERBOSE("Destroying cplib_mem_chunk_t %p with mem size %zu. Remaining cplib_mem_chunk_t %lld\n", (void *) chunk,
                chunk->size, allocated_chunks);
    cplib_free(chunk->mem);
    chunk->mem = NULL;
    chunk->size = 0;
    chunk->taken = 0;
    chunk->destroy = NULL;
    chunk->recycle = NULL;
    cplib_free(chunk);
    return CPLIB_ERR_SUCCESS;
}

int cplib_mem_chunk_append(struct cplib_mem_chunk_t *self, void *data, size_t size) {
    if (self->size - self->taken < size) {
        return CPLIB_ERR_ARG;
    }

    memcpy(((uint8_t*)self->mem) + self->taken, data, size);

    self->taken += size;

    return CPLIB_ERR_SUCCESS;
}


cplib_mem_chunk_t *cplib_create_chunk(size_t size) {
    cplib_mem_chunk_t *chunk = (cplib_mem_chunk_t *) cplib_destroyable_new(sizeof(cplib_mem_chunk_t));
    if (!chunk) {
        LOG_DEBUG("Cannot allocate chunk. Out of memory\n");
        return NULL;
    }

    chunk->size = size;
    chunk->taken = 0;
    chunk->recycle = cplib_mem_chunk_recycle;
    chunk->destroy = (cplib_independent_mutator_f) cplib_destroy_chunk;
    chunk->append = (cplib_mem_chunk_append_f) cplib_mem_chunk_append;

    allocated_chunks++;
    LOG_VERBOSE("Created cplib_mem_chunk_t %p with mem size %zu\n", (void *) chunk, chunk->size);

    return chunk;
}

struct cplib_mem_chunk_t *cplib_allocate_mem_chunk(size_t size) {
    cplib_mem_chunk_t *chunk = cplib_create_chunk(size);
    if (!chunk) {
        return NULL;
    }

    chunk->mem = (void *) cplib_malloc(size);

    if (!chunk->mem) {
        LOG_DEBUG("Cannot allocate chunk of size %zu. Out of memory\n", size);
        cplib_free(chunk);
        return NULL;
    }

    return chunk;
}

cplib_mem_chunk_t *cplib_mem_chunk_new(void *data, size_t size) {
    cplib_mem_chunk_t *chunk = cplib_allocate_mem_chunk(size);
    if (!chunk) {
        return NULL;
    }

    memcpy(chunk->mem, data, size);
    chunk->taken = size;

    return chunk;
}

cplib_mem_chunk_t *cplib_mem_chunk_str_new(const char *string) {
    size_t size;
    cplib_mem_chunk_t *chunk;

    size = strlen(string);
    chunk = cplib_allocate_mem_chunk(size + 1);
    if (!chunk) {
        return NULL;
    }

    memcpy(chunk->mem, string, size);
    chunk->taken = size + 1;
    ((uint8_t *) chunk->mem)[size] = '\0';
    return chunk;
}


#define REF_COUNT_SIZE sizeof(uint64_t)

static unsigned long long allocated;

void *cplib_malloc(size_t size) {
    uint64_t *mem;

    mem = (uint64_t *) malloc(size + REF_COUNT_SIZE);
    if (!mem) {
        return NULL;
    }

    LOG_MEM("Allocated: %p with size %zu\n", (void *) mem, size);

    memset(mem, 0, size + REF_COUNT_SIZE);
    mem[0] = 1;
    allocated++;
    return ((uint8_t *) mem) + REF_COUNT_SIZE;
}

void cplib_free(void *ptr) {
    if (!ptr) {
        LOG_MEM("Freeing NULL\n");
        return;
    }
    uint64_t *mem;
    uint64_t ref_count;

    mem = (uint64_t *) ((uint8_t *) ptr - REF_COUNT_SIZE);
    mem[0]--;
    ref_count = mem[0];

    LOG_MEM("Put: %p\n", (void *) mem);

    if (ref_count > 0) {
        return;
    }
    allocated--;
    free(mem);
    LOG_MEM("Freeing: %p\n", (void *) mem);
    LOG_MEM("Remaining allocated chunks: %lld\n", allocated);
}

void cplib_hold(void *ptr) {
    uint64_t *mem;

    mem = (uint64_t *) ptr - REF_COUNT_SIZE;
    mem[0]++;

    LOG_MEM("Hold: %p\n", (void *) mem);
}

int cplib_destroyable_destroy(cplib_destroyable_t *destroyable) {
    LOG_VERBOSE("Destroying cplib_destroyable_t %p\n", (void *) destroyable);
    destroyable->ref_count = 0;
    cplib_free(destroyable);
    return CPLIB_ERR_SUCCESS;
}

int cplib_destroyable_put(void *destroyable_ptr) {
    int ret;
    cplib_destroyable_t *destroyable = (cplib_destroyable_t *) destroyable_ptr;
    destroyable->ref_count--;
    LOG_MEM("Destroyable put: %p\n", (void *) destroyable);

    if (destroyable->ref_count < 0) {
        LOG_MEM("Destroyable double free: %p\n", (void *) destroyable);
        return CPLIB_ERR_MEM;
    }

    if (destroyable->ref_count == 0) {
        LOG_MEM("Destroyable reached ref_count == 0: %p\n", (void *) destroyable);
        if (!destroyable->destroy) {
            return CPLIB_ERR_SUCCESS;
        }

        if (destroyable->destroy == (cplib_independent_mutator_f) cplib_destroyable_put) {
            cplib_destroyable_destroy(destroyable);
            return CPLIB_MEM_DESTROY;
        }

        ret = destroyable->destroy(destroyable);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MEM("Failed to destroy: %p\n", (void *) destroyable);
        };

        return CPLIB_MEM_DESTROY;
    }

    return CPLIB_MEM_KEEP;
}

int cplib_destroyable_hold(void *destroyable_ptr) {
    cplib_destroyable_t *destroyable = (cplib_destroyable_t *) destroyable_ptr;
    LOG_MEM("Destroyable hold: %p\n", (void *) destroyable);
    destroyable->ref_count++;
    return CPLIB_ERR_SUCCESS;
}


cplib_destroyable_t *cplib_destroyable_new(size_t size) {
    cplib_destroyable_t *destroyable = (cplib_destroyable_t *) cplib_malloc(size);
    destroyable->ref_count = 1;
    destroyable->destroy = (cplib_independent_mutator_f) cplib_destroyable_destroy;
    return destroyable;
}
