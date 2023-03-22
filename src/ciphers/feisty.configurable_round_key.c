/**
 * Karel Chanivecky 2023.
 */

/*
 * Expected key avalanche effect for a bit in position 1 in the first round
 *
 * 1  2  3  4  5  6  7  8
 * 1  25 9 17  1 25  9 17
 *    2 26 10 18  2 26 10
 *       3 27 11 19  3 27
 *          4 28 12 20  4
 *            5  29 13 21
 *                6 30 14
 *                  7  31
 *                      8
 */

#include <dc_utils/dlinked_list.h>
#include <string.h>
#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"

static char error_text[KCRYPT_ERROR_TEXT_MAX_LENGTH] = {0};

typedef uint32_t feisty_key_t;
static int LAST_BIT_SHIFT_SIZE = (sizeof(feisty_key_t) * 8) - 1;
static const feisty_key_t DEFAULT_ROUND_KEYS[] = {
        0xdddddddd,
        0xeeeeeeee,
        0xaaaaaaaa,
        0xdddddddd,
        0xbbbbbbbb,
        0xeeeeeeee,
        0xeeeeeeee,
        0xffffffff
};

struct feisty_options_t {
    cplib_mem_chunk_t **keys;
    enum cplib_proc_type process;
};

typedef struct feisty_options_t feisty_options_t;

static feisty_options_t options = {0};


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
    processed = *processed_ptr;

    if (!processed) {
        processed = cplib_allocate_mem_chunk(key->taken);
    }

    if (!processed) {
        LOG_DEBUG("Failed to allocate memory for processed data\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    if (processed->size < key->taken) {
        LOG_DEBUG("Passed processed counter is smaller than needed. given %zu < needed %zu\n", processed->size,
                  key->taken);
        ret = CPLIB_ERR_SIZE_MISMATCH;
        goto cleanup;
    }

    mem = data->mem;
    temp = mem[0];
    mem[0] = mem[2];
    mem[2] = mem[1];
    mem[1] = mem[3];
    mem[3] = temp;
    ret = block_manipulator->xor(block_manipulator, data, key, processed_ptr);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to xor data\n");
        goto cleanup;
    }

    ret = CPLIB_ERR_SUCCESS;

    *processed_ptr = processed;

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

int load_round_keys(const feisty_key_t *round_keys) {
    int ret;
    int i;
    cplib_mem_chunk_t *key;

    options.keys = cplib_malloc(sizeof(cplib_mem_chunk_t *) * 8);
    if (!options.keys) {
        LOG_DEBUG("Failed to allocate memory for round key\n");
        strcpy(error_text, "Out of memory");
        return CPLIB_ERR_MEM;
    }

    for (i = 0; i < 8; i++) {
        key = cplib_allocate_mem_chunk(sizeof(feisty_key_t));
        if (!key) {
            LOG_DEBUG("Failed to allocate memory for round key\n");
            strcpy(error_text, "Out of memory");
            ret = CPLIB_ERR_MEM;
            goto error_cleanup;
        }

        key->append(key, &round_keys[i], sizeof(feisty_key_t));

        if (options.process == CPLIB_PROC_DECRYPT) {
            options.keys[8 - 1 - i] = key;
        } else {
            options.keys[i] = key;
        }
    }

    return CPLIB_ERR_SUCCESS;

    error_cleanup:

    for (i -= 1; i >= 0; i--) {
        options.keys[i]->destroy(options.keys[i]);
    }

    cplib_free(options.keys);

    return ret;
}


int feisty_cipher_round_key_provider_initialize(cplib_round_key_provider_base_t *self, cplib_mem_chunk_t *root_key) {
    int ret;
    feisty_key_t keys[8] = {0};
    feisty_key_t key_val;
    uint8_t left_bit;

    if (options.keys) {
        self->round_keys_count = 8;
        self->round_keys = options.keys;
        options.keys = NULL;
        return CPLIB_ERR_SUCCESS;
    }


    if (root_key->taken != sizeof(feisty_key_t)) {
        LOG_DEBUG("This cipher requires a %zub key\n", sizeof(feisty_key_t) * 8);
        sprintf(error_text, "This cipher requires a %zub key", sizeof(feisty_key_t) * 8);
        return CPLIB_ERR_KEY_SIZE;
    }

    key_val = *(feisty_key_t *) (root_key->mem);

    for (size_t i = 0; i < 8; i++) {
        // rotate left
        for (int j = 0; j < 5; j++) {
            left_bit = ((key_val & (1 << LAST_BIT_SHIFT_SIZE)) >> LAST_BIT_SHIFT_SIZE);
            key_val <<= 1;
            key_val |= left_bit;
        }
        keys[0] = key_val;
    }

    ret = load_round_keys(keys);

    if (ret != CPLIB_ERR_SUCCESS) {
        return ret;
    }

    return feisty_cipher_round_key_provider_initialize(self, root_key);
}


cplib_key_provider_base_t *allocate_key_provider(cplib_key_provider_factory_base_t *self) {
    CPLIB_UNUSED_PARAM(self);
    return (cplib_key_provider_base_t *) cplib_round_key_provider_new2(
            (cplib_mem_chunk_func) feisty_cipher_round_key_provider_initialize);
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
        LOG_DEBUG("Failed to allocate block manipulator\n");
        goto error_cleanup;
    }

    feistel = (cplib_cipher_base_t *) cplib_feistel_cipher_new(feisty_cipher_round_function,
                                                               NULL,
                                                               block_manipulator);
    cplib_destroyable_put(block_manipulator);
    if (!feistel) {
        LOG_DEBUG("Failed to allocate cipher\n");
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

int feisty_main_key_provider_initialize(cplib_keyed_key_provider_t *self, cplib_mem_chunk_t *root_key) {
    if (root_key->taken != sizeof(uint32_t)) {
        LOG_MSG("This cipher requires a %zub key\n", sizeof(uint32_t) * 8);
    }

    self->key = root_key;
    cplib_destroyable_hold(root_key);

    return CPLIB_ERR_SUCCESS;
}

cplib_key_provider_base_t *feisty_cipher_allocate_key_provider(void) {
    cplib_key_provider_base_t *key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        return NULL;
    }

    key_provider->initialize = (cplib_mem_chunk_func) feisty_main_key_provider_initialize;

    return key_provider;
}

int parse_options(int argc, const char **argv) {
    int ret;
    feisty_key_t round_keys[8] = {0};
    unsigned long long key;

    if (argc < 2) {
        LOG_DEBUG("No args provided. Using default behaviour.\n");
        return CPLIB_ERR_SUCCESS;
    }

    if (argv[1][0] != '-') {
        LOG_DEBUG("Args provided, but did not start with option\n");
        strcpy(error_text, "Arguments for cipher must have an option after the CIPHER header");
        return CPLIB_ERR_ARG;
    }

    if (argv[1][1] == 'd') {
        LOG_DEBUG("Using default round keys\n");
        return load_round_keys(DEFAULT_ROUND_KEYS);
    }

    if (argv[1][1] == '-') {
        LOG_DEBUG("Passed no options\n");
        return CPLIB_ERR_SUCCESS;
    }

    if (argv[1][1] != 'r') {
        LOG_DEBUG("Invalid option passed\n");
        sprintf(error_text, "option is invalid: %c", argv[1][1]);
        return CPLIB_ERR_ARG;
    }

    if (argc < 10) {
        LOG_DEBUG("Did not provide 8 round keys\n");
        strcpy(error_text, "Did not provide 8 round keys");
        return CPLIB_ERR_ARG;
    }

    for (int i = 2; i < 10; i++) {
        ret = cplib_safe_strtoull(argv[i], NULL, 16, &key);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to parse key: %s\n", argv[i]);
            return CPLIB_ERR_ARG;
        }

        round_keys[i - 2] = key;
    }

    ret = load_round_keys(round_keys);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to parse cipher options\n");
        return ret;
    }
    LOG_VERBOSE("Parse cipher options\n");

    return CPLIB_ERR_SUCCESS;
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

    int ret;

    options.process = proc_type;

    ret = parse_options(argc, argv);
    if (ret != CPLIB_ERR_SUCCESS) {
        return ret;
    }

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

    LOG_VERBOSE("Cipher ready to run\n");

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
        "Usage -- " KCRYPT_CLI_CIPHER_ARGS_HEADER " [-d | -r]\n"
        "\n"
        "-d use default round keys. Ignore kcrypt -l or -k arg. Note that for decryption the given round keys will be reversed.\n"
        "   In other words, the keys must be provided in the same order as they were given to the encryption process\n"
        "-r <round key 1> <round key 2> <round key ..> <round key 8>: Specify round keys in hexadecimal. Ignore kcrypt -l or -k arg.\n"
        "If -r or -d are not provided will generate round keys based off the kcrypt arg -k or -l\n"
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
