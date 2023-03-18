/**
 * Karel Chanivecky 2023.
 */


#include "cplib_utils.h"
#include "cplib_log.h"
#include "kcrypt.h"

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
    return cplib_cipher_new((cplib_process_f) xor_cipher_proc_function);
}

cplib_cipher_factory_base_t *cipher_get_cipher_factory(enum cplib_proc_type process_type) {
    return cplib_cipher_factory_new(allocate_xor_cipher);
}


int xor_key_provider_initialize(cplib_keyed_key_provider_t *self, cplib_mem_chunk_t *root_key) {
    if (root_key->taken != sizeof(uint32_t)) {
        LOG_MSG("This cipher requires a %zub key\n", sizeof(uint32_t) * 8);
    }

    self->key = root_key;
    cplib_destroyable_hold(root_key);

    return CPLIB_ERR_SUCCESS;
}

cplib_key_provider_base_t * cipher_allocate_key_provider(cplib_key_provider_factory_base_t * self) {
    cplib_key_provider_base_t * key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        return NULL;
    }

    key_provider->initialize = (cplib_mem_chunk_func) xor_key_provider_initialize;

    return key_provider;
}


cplib_key_provider_factory_base_t * cipher_get_key_provider_factory(void) {
    return cplib_key_provider_factory_new(cipher_allocate_key_provider);
}

int xor_cipher_get_suite(
        enum cplib_proc_type proc_type,
        int argc,
        const char **argv,
        cplib_cipher_factory_base_t **cipher_factory,
        cplib_key_provider_factory_base_t **key_provider_factory,
        cplib_block_padder_base_t ** padder) {

    return CPLIB_ERR_SUCCESS;
}


int xor_cipher_module_destroy(kcrypt_shared_module_api_t * cipher_module) {
    return CPLIB_ERR_SUCCESS;
}

size_t supported_key_sizes[] = {KCRYPT_ANY_KEY_SIZE};

const char *supported_modes[] = {
        KCRYPT_MODE_ECB,
        KCRYPT_MODE_CBC,
        KCRYPT_MODE_CTR,
        KCRYPT_MODE_OFB,
        KCRYPT_MODE_CFB
};

int kcrypt_init_cipher_module_api(kcrypt_cipher_module_api_t * cipher_module) {
    cipher_module->get_cipher = xor_cipher_get_suite;
    cipher_module->supported_modes = supported_modes;
    cipher_module->supported_mode_count = 5;
    cipher_module->supported_key_sizes = supported_key_sizes;
    cipher_module->supported_key_sizes_count = KCRYPT_ANY_KEY_SIZE;
    cipher_module->block_to_key_size_ratio = 1;
    cipher_module->destroy = (cplib_independent_mutator_f) xor_cipher_module_destroy;
    return CPLIB_ERR_SUCCESS;
}

