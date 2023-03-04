/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_CIPHRAMEWORKLIB_H
#define SOURCES_CIPHRAMEWORKLIB_H

#include <stdint.h>

#include "mem_chunk.h"

enum cplib_block_position {
    START,
    CENTER,
    END
};


typedef int (*cplib_process_func)(mem_chunk_t * data, mem_chunk_t key,)

struct cplib_cipher_driver_s {

};


#endif //SOURCES_CIPHRAMEWORKLIB_H
