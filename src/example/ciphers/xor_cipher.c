/**
 * Karel Chanivecky 2023.
 */


#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"

int xor_cipher_proc_function(struct cplib_cipher_base_t *self,
                             cplib_mem_chunk_t *data,
                             cplib_mem_chunk_t *key,
                             enum cplib_block_position position,
                             cplib_mem_chunk_t **processed_ptr) {
    CPLIB_UNUSED_PARAM(self);
    CPLIB_UNUSED_PARAM(position);

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
        LOG_MSG("Passed processed buffer is smaller than needed. given %zu < needed %zu\n", processed->size,
                key->taken);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    ret = block_manipulator->xor(block_manipulator, data, key, processed_ptr);
    cplib_destroyable_put(block_manipulator);
    return ret;
}

cplib_cipher_base_t *allocate_xor_cipher(cplib_cipher_factory_base_t *self) {
    CPLIB_UNUSED_PARAM(self);

    return cplib_cipher_new((cplib_process_f) xor_cipher_proc_function);
}

cplib_cipher_factory_base_t *xor_cipher_get_cipher_factory(void) {
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

cplib_key_provider_base_t *xor_cipher_allocate_key_provider(void) {
    cplib_key_provider_base_t *key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        return NULL;
    }

    key_provider->initialize = (cplib_mem_chunk_func) xor_key_provider_initialize;

    return key_provider;
}


int xor_cipher_get_suite(
        int argc,
        const char **argv,
        enum cplib_proc_type proc_type,
        cplib_cipher_factory_base_t **cipher_factory,
        cplib_key_provider_base_t **key_provider) {
    CPLIB_UNUSED_PARAM(argc);
    CPLIB_UNUSED_PARAM(argv);
    CPLIB_UNUSED_PARAM(proc_type);

    *cipher_factory = (cplib_cipher_factory_base_t *) xor_cipher_get_cipher_factory();
    if (!*cipher_factory) {
        return CPLIB_ERR_MEM;
    }

    *key_provider = xor_cipher_allocate_key_provider();
    if (!*key_provider) {
        (*cipher_factory)->destroy(*cipher_factory);
        *cipher_factory = NULL;
        return CPLIB_ERR_MEM;
    }

    return CPLIB_ERR_SUCCESS;
}


int xor_cipher_module_destroy(kcrypt_shared_module_api_t *cipher_module) {
    CPLIB_UNUSED_PARAM(cipher_module);

    return CPLIB_ERR_SUCCESS;
}

static size_t supported_key_sizes[] = {KCRYPT_ANY_KEY_SIZE};
const char *supported_modes[] = {
        KCRYPT_MODE_ANY
};
static char *help_text =
        "Usage -- " KCRYPT_CLI_CIPHER_ARGS_HEADER "\n"
        "Supported modes: [" KCRYPT_MODE_ANY "]\n"
        "Supported key sizes: [" KCRYPT_ANY_KEY_SIZE_STR "]\n";

int kcrypt_init_cipher_module_api(kcrypt_cipher_module_api_t *cipher_module) {
    cipher_module->get_cipher = (kcrypt_get_cipher_f) xor_cipher_get_suite;
    cipher_module->supported_modes = supported_modes;
    cipher_module->supported_mode_count = 1;
    cipher_module->supported_key_sizes = supported_key_sizes;
    cipher_module->supported_key_sizes_count = 1;
    cipher_module->block_to_key_size_ratio = 1;
    cipher_module->help_text = help_text;
    cipher_module->mandatory_mode = NULL;
    cipher_module->destroy = (cplib_independent_mutator_f) xor_cipher_module_destroy;
    cipher_module->struct_size = sizeof(kcrypt_cipher_module_api_t);

    return CPLIB_ERR_SUCCESS;
}

