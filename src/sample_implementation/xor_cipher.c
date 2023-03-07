/**
 * Karel Chanivecky 2023.
 */


#include "xor_cipher.h"
#include "cplib_utils.h"
#include "cplib_log.h"


int xor_cipher_proc_function(struct cplib_cipher_base_t *base_self,
                             cplib_mem_chunk_t *data,
                             cplib_mem_chunk_t *key,
                             enum cplib_block_position position,
                             cplib_mem_chunk_t **processed_ptr) {

    int ret;

    cplib_block_manipulator_base_t *block_manipulator;
    cplib_mem_chunk_t *processed;

    block_manipulator = cplib_simple_block_manipulator_new();
    if (!*processed_ptr) {
        *processed_ptr = cplib_allocate_mem_chunk(key->taken);
        if (!*processed_ptr) {
            LOG_MSG("Failed to allocate memory for processed data\n");
            return CPLIB_ERR_MEM;
        }
    }

    processed = *processed_ptr;

    if (processed->size < key->taken) {
        LOG_MSG("Passed processed buffer is smaller than needed. given %zu < needed %zu\n", processed->size, key->taken);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    ret = block_manipulator->xor(block_manipulator, data, key, processed_ptr);
    cplib_destroyable_put(block_manipulator);
    return ret;
}

cplib_cipher_base_t *allocate_xor_cipher(void) {
    return cplib_cipher_new(xor_cipher_proc_function);
}

cplib_cipher_factory_base_t *get_xor_cipher_factory(enum cplib_proc_type process_type) {
    return cplib_cipher_factory_new(allocate_xor_cipher);
}

