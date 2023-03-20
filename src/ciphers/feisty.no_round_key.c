/**
 * Karel Chanivecky 2023.
 */


#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"

static char error_text[KCRYPT_ERROR_TEXT_MAX_LENGTH] = {0};


int feisty_cipher_proc_function(cplib_destroyable_t *base_self,
                                cplib_mem_chunk_t *data,
                                cplib_mem_chunk_t *key,
                                enum cplib_block_position position,
                                cplib_mem_chunk_t **processed_ptr) {
    CPLIB_UNUSED_PARAM(base_self);
    CPLIB_UNUSED_PARAM(position);
    int ret;
    uint8_t temp;
    uint8_t *mem;
    cplib_block_manipulator_base_t *block_manipulator;
    cplib_mem_chunk_t *processed;

    block_manipulator = cplib_simple_block_manipulator_new();
    if (!*processed_ptr) {
        *processed_ptr = cplib_allocate_mem_chunk(key->taken);
        if (!*processed_ptr) {
            LOG_MSG("Failed to allocate memory for processed data\n");
            ret = CPLIB_ERR_MEM;
            goto cleanup;
        }
    }

    processed = *processed_ptr;

    if (processed->size < key->taken) {
        LOG_MSG("Passed processed buffer is smaller than needed. given %zu < needed %zu\n", processed->size,
                key->taken);
        ret = CPLIB_ERR_SIZE_MISMATCH;
        goto cleanup;
    }

    mem = data->mem;
    temp = mem[0];
    mem[0] = mem[2];
    mem[0] = mem[2];
    mem[2] = mem[1];
    mem[1] = temp;
    ret = block_manipulator->xor(block_manipulator, data, key, processed_ptr);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to xor data\n");
        goto cleanup;
    }

    ret = CPLIB_ERR_SUCCESS;

    cleanup:
    CPLIB_PUT_IF_EXISTS(block_manipulator);
    return ret;
}

int feisty_cipher_round_function(cplib_destroyable_t *round_f_self,
                                 cplib_mem_chunk_t *data,
                                 cplib_mem_chunk_t *key,
                                 enum cplib_block_position position,
                                 cplib_mem_chunk_t **processed_ptr) {
    CPLIB_UNUSED_PARAM(round_f_self);
    return feisty_cipher_proc_function(round_f_self, data, key, position, processed_ptr);
}

cplib_keyed_key_provider_t *allocate_key_provider(cplib_key_provider_factory_base_t *self) {
    CPLIB_UNUSED_PARAM(self);
    return cplib_keyed_key_provider_new3();
}


cplib_cipher_base_t *allocate_feisty_cipher(cplib_cipher_factory_base_t *self) {
    CPLIB_UNUSED_PARAM(self);
    cplib_cipher_base_t *feistel = NULL;
    cplib_cipher_provider_base_t *cipher_provider = NULL;
    cplib_key_provider_factory_base_t *key_provider_factory = NULL;
    cplib_cipher_base_t *round_cipher = NULL;
    cplib_block_manipulator_base_t *block_manipulator = NULL;

    block_manipulator = cplib_simple_block_manipulator_new();
    if (!block_manipulator) {
        LOG_MSG("Failed to allocate block manipulator\n");
        goto error_cleanup;
    }

    feistel = (cplib_cipher_base_t *) cplib_feistel_cipher_new(feisty_cipher_round_function,
                                                               NULL,
                                                               block_manipulator);
    cplib_destroyable_put(block_manipulator);
    if (!feistel) {
        LOG_MSG("Failed to allocate cipher\n");
        goto error_cleanup;
    }

    key_provider_factory = cplib_key_provider_factory_new((cplib_key_provider_allocator_f) allocate_key_provider);


    round_cipher = (cplib_cipher_base_t *) cplib_round_cipher_new2(feistel, 8, key_provider_factory);

    return round_cipher;
    error_cleanup:
    CPLIB_PUT_IF_EXISTS(feistel);
    CPLIB_PUT_IF_EXISTS(key_provider_factory);
    CPLIB_PUT_IF_EXISTS(cipher_provider);
    CPLIB_PUT_IF_EXISTS(round_cipher);
    return NULL;
}

cplib_cipher_factory_base_t *feisty_cipher_get_cipher_factory(void) {
    return cplib_cipher_factory_new(allocate_feisty_cipher);
}


int feisty_cipher_key_provider_initialize(cplib_keyed_key_provider_t *self, cplib_mem_chunk_t *root_key) {

    if (root_key->taken != sizeof(uint32_t)) {
        LOG_MSG("This cipher requires a %zub key\n", sizeof(uint32_t) * 8);
        return CPLIB_ERR_KEY_SIZE;
    }

    self->key = root_key;

    return CPLIB_ERR_SUCCESS;
}

cplib_key_provider_base_t *feisty_cipher_allocate_key_provider(void) {
    cplib_key_provider_base_t *key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        return NULL;
    }

    key_provider->initialize = (cplib_mem_chunk_func) feisty_cipher_key_provider_initialize;

    return key_provider;
}


int feisty_cipher_get_suite(
        int argc,
        const char **argv,
        enum cplib_proc_type proc_type,
        cplib_cipher_factory_base_t **cipher_factory,
        cplib_key_provider_base_t **key_provider) {
    CPLIB_UNUSED_PARAM(argc);
    CPLIB_UNUSED_PARAM(argv);
    CPLIB_UNUSED_PARAM(proc_type);

    *cipher_factory = (cplib_cipher_factory_base_t *) feisty_cipher_get_cipher_factory();
    if (!*cipher_factory) {
        return CPLIB_ERR_MEM;
    }

    *key_provider = feisty_cipher_allocate_key_provider();
    if (!*key_provider) {
        (*cipher_factory)->destroy(*cipher_factory);
        *cipher_factory = NULL;
        return CPLIB_ERR_MEM;
    }

    return CPLIB_ERR_SUCCESS;
}

int feisty_cipher_module_destroy(kcrypt_shared_module_api_t *cipher_module) {
    CPLIB_UNUSED_PARAM(cipher_module);
    return CPLIB_ERR_SUCCESS;
}

static size_t supported_key_sizes[] = {4};
static const char *supported_modes[] = {
        KCRYPT_MODE_ANY
};

char *get_error_text(kcrypt_cipher_module_api_t *self) {
    CPLIB_UNUSED_PARAM(self);
    return error_text;
}


static char *help_text =
        "Usage -- " KCRYPT_CLI_CIPHER_ARGS_HEADER "\n"
        "Supported modes: [" KCRYPT_MODE_ANY "]\n"
        "Supported key sizes: [32b]\n";

int kcrypt_lib_init(kcrypt_cipher_module_api_t *cipher_module) {

    if (cipher_module->struct_size == sizeof(kcrypt_cipher_module_api_t)) {
        cipher_module->get_cipher = (kcrypt_get_cipher_f) feisty_cipher_get_suite;
        cipher_module->supported_modes = (const char **) supported_modes;
        cipher_module->supported_mode_count = 1;
        cipher_module->supported_key_sizes = supported_key_sizes;
        cipher_module->supported_key_sizes_count = 1;
        cipher_module->block_to_key_size_ratio = 2;
        cipher_module->mandatory_mode = NULL;
        cipher_module->destroy = (cplib_independent_mutator_f) feisty_cipher_module_destroy;
    }

    cipher_module->help_text = help_text;
    cipher_module->get_error_text = (error_text_f) get_error_text;

    return CPLIB_ERR_SUCCESS;
}
