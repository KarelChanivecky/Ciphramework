/**
 * Karel Chanivecky 2023.
 */



#ifndef SOURCES_MEM_H
#define SOURCES_MEM_H

#include <stdint.h>

struct mem_chunk_t {
    void * mem;
    size_t size;
    size_t taken;
};

typedef struct mem_chunk_t mem_chunk_t;

mem_chunk_t * cplib_new_chunk(size_t size);

void cplib_destroy_chunk(mem_chunk_t * chunk);

#endif //SOURCES_MEM_H
