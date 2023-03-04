/**
 * Karel Chanivecky 2023.
 */
#include <stdlib.h>

#include "mem_chunk.h"

mem_chunk_t * new_chunk(size_t size) {
    mem_chunk_t * chunk = (mem_chunk_t*) malloc(size);
    if ()
    chunk->size = size;
    chunk->taken = 0;
    return chunk;
}

void destroy_chunk(mem_chunk_t ** chunk_ptr) {
    mem_chunk_t * chunk = *chunk_ptr;
    chunk->size = 0;
    chunk->taken = 0;
    free(chunk);
    *chunk_ptr = NULL;
}
