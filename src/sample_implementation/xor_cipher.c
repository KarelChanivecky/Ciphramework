/**
 * Karel Chanivecky 2023.
 */

#ifdef KCRYPT_XOR_CIPHER

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

cplib_cipher_base_t *allocate_xor_cipher(cplib_cipher_factory_base_t * self) {
    return cplib_cipher_new(xor_cipher_proc_function);
}

cplib_cipher_factory_base_t *cipher_get_cipher_factory(enum cplib_proc_type process_type) {
    return cplib_cipher_factory_new(allocate_xor_cipher);
}


int xor_key_provider_initialize(cplib_key_provider_base_t* self, cplib_mem_chunk_t * key) {
    if (key->taken != sizeof(uint32_t)) {
        LOG_MSG("This cipher requires a %zub key\n", sizeof(uint32_t) * 8);
    }


}

cplib_key_provider_base_t * cipher_allocate_key_provider(cplib_key_provider_factory_base_t * self) {
    cplib_key_provider_base_t * key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        return NULL;
    }


}


cplib_key_provider_factory_base_t * cipher_get_key_provider_factory(void) {
    return cplib_key_provider_factory_new(cipher_allocate_key_provider);
}

size_t cipher_block_to_key_ratio(void) {
    return 1;
}


#endif // KCRYPT_XOR_CIPHER
