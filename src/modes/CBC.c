/**
 * Karel Chanivecky 2023.
 */

#include <string.h>
#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"

static char error_text[KCRYPT_ERROR_TEXT_MAX_LENGTH] = {0};
static cplib_block_manipulator_base_t *block_manipulator = NULL;

struct cbc_mode_t {
    cplib_mode_base_t;
    cplib_mem_chunk_t *buffer;
};

typedef struct cbc_mode_t cbc_mode_t;

int cbc_mode_store_data(cbc_mode_t *self, cplib_mem_chunk_t *data) {

    LOG_VERBOSE("CBC mode storing data\n");
    return self->buffer->recycle(self->buffer, data->mem, data->taken);
}

int cbc_mode_proc_data(cbc_mode_t *self, cplib_mem_chunk_t *data, cplib_mem_chunk_t **output) {
    LOG_VERBOSE("CBC mode processing data\n");
    int ret;

    if (!block_manipulator) {
        block_manipulator = cplib_simple_block_manipulator_new();
    }

    if (!block_manipulator) {
        LOG_DEBUG("Failed to allocate block manipulator\n");
        strcpy(error_text, "Out of memory");
        return CPLIB_ERR_MEM;
    }

    if (*output == NULL) {
        *output = cplib_allocate_mem_chunk(data->taken);
    }

    if (!*output) {
        LOG_DEBUG("Failed to allocate memory for output block\n");
        strcpy(error_text, "Out of memory");
        return CPLIB_ERR_MEM;
    }

    if ((*output)->size < data->taken) {
        LOG_DEBUG("Output chunk is too small\n");
        strcpy(error_text, "Application error");
        return CPLIB_ERR_ARG;
    }

    ret = block_manipulator->xor(block_manipulator, self->buffer, data, output);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to perform XOR operation\n");
        sprintf(error_text, "XOR operation failed with code: %d", ret);
        return ret;
    }

    return CPLIB_ERR_SUCCESS;
}

int cbc_mode_encrypt_pre_transform(cbc_mode_t *self,
                                   cplib_mem_chunk_t *data,
                                   cplib_mem_chunk_t *key,
                                   enum cplib_block_position position,
                                   cplib_mem_chunk_t **out) {
    CPLIB_UNUSED_PARAM(key);
    CPLIB_UNUSED_PARAM(position);
    return cbc_mode_proc_data(self, data, out);
}

int cbc_mode_encrypt_post_transform(cbc_mode_t *self,
                                    cplib_mem_chunk_t *processed,
                                    cplib_mem_chunk_t *unpadded,
                                    cplib_mem_chunk_t *key,
                                    enum cplib_block_position position,
                                    cplib_mem_chunk_t **out) {
    CPLIB_UNUSED_PARAM(unpadded);
    CPLIB_UNUSED_PARAM(key);
    CPLIB_UNUSED_PARAM(position);
    *out = processed;
    cplib_destroyable_hold(processed);
    return cbc_mode_store_data(self, processed);
}

int cbc_mode_decrypt_pre_transform(cbc_mode_t *self,
                                   cplib_mem_chunk_t *data,
                                   cplib_mem_chunk_t *key,
                                   enum cplib_block_position position,
                                   cplib_mem_chunk_t **out) {
    CPLIB_UNUSED_PARAM(self);
    CPLIB_UNUSED_PARAM(data);
    CPLIB_UNUSED_PARAM(key);
    CPLIB_UNUSED_PARAM(position);
    *out = data;
    cplib_destroyable_hold(data);
    return CPLIB_ERR_SUCCESS;
}

int cbc_mode_decrypt_post_transform(cbc_mode_t *self,
                                    cplib_mem_chunk_t *processed,
                                    cplib_mem_chunk_t *unpadded,
                                    cplib_mem_chunk_t *key,
                                    enum cplib_block_position position,
                                    cplib_mem_chunk_t **out) {
    CPLIB_UNUSED_PARAM(key);
    CPLIB_UNUSED_PARAM(position);
    int ret;

    ret = cbc_mode_proc_data(self, processed, out);
    if (!ret) {
        LOG_DEBUG("Failed to XOR\n");
        return ret;
    }

    return cbc_mode_store_data(self, unpadded);
}

int cbc_mode_destroy(cbc_mode_t *self) {
    CPLIB_PUT_IF_EXISTS(self->buffer);
    return cplib_mode_base_destroy((cplib_mode_base_t *) self);
}

int cbc_mode_allocate(cplib_mem_chunk_t *buffer, enum cplib_proc_type process, cbc_mode_t **mode) {
    if (process == CPLIB_PROC_ENCRYPT) {
        *mode = (cbc_mode_t *) cplib_mode_base_new(sizeof(cbc_mode_t),
                                                   (cplib_mode_pre_transform_f) cbc_mode_encrypt_pre_transform,
                                                   (cplib_mode_post_transform_f) cbc_mode_encrypt_post_transform);
    } else if (process == CPLIB_PROC_DECRYPT) {
        *mode = (cbc_mode_t *) cplib_mode_base_new(sizeof(cbc_mode_t),
                                                   (cplib_mode_pre_transform_f) cbc_mode_decrypt_pre_transform,
                                                   (cplib_mode_post_transform_f) cbc_mode_decrypt_post_transform);
    } else {
        LOG_DEBUG("Invalid process type passed.\n");
        strcpy(error_text, "Invalid process type passed.\n");
        return CPLIB_ERR_ARG;
    }

    if (!*mode) {
        LOG_DEBUG("Failed to allocate memory for mode.\n");
        strcpy(error_text, "Out of memory\n");
        return CPLIB_ERR_MEM;
    }

    (*mode)->buffer = buffer;
    (*mode)->destroy = (cplib_independent_mutator_f) cbc_mode_destroy;
    return CPLIB_ERR_SUCCESS;
}

int cbc_mode_parse_args(int argc, const char **argv, size_t block_iteration_size,
                        cplib_mem_chunk_t **initialization_vector) {
    int ret;
    cplib_mem_chunk_t *iv = NULL;

    if (argc < 3) {
        LOG_DEBUG("Did not provide initialization vector.\n");
        strcpy(error_text, "Did not provide initialization vector");
        return CPLIB_ERR_ARG;
    }

    if (argv[1][0] != '-') {
        LOG_DEBUG("Args provided, but did not start with option\n");
        strcpy(error_text, "Arguments for cipher must have an option after the CIPHER header");
        return CPLIB_ERR_ARG;
    }

    if (argv[1][1] == 'i') {
        LOG_DEBUG("Getting initialization vector from cli args\n");
        iv = cplib_mem_chunk_str_new(argv[2]);
        if (!iv) {
            LOG_DEBUG("Failed to allocate initialization vector\n");
            strcpy(error_text, "Out of memory");
            return CPLIB_ERR_MEM;
        }
        iv->taken--; // str new allocates 1 extra byte for \0
        *initialization_vector = iv;
        if (iv->taken != block_iteration_size) {
            LOG_DEBUG("Given initialization vector size does not match the block size\n");
            cplib_destroyable_put(iv);
            sprintf(error_text, "Initialization vector is not the needed size: %zu", block_iteration_size);
            return CPLIB_ERR_ARG;
        }
        return CPLIB_ERR_SUCCESS;
    }

    if (argv[1][1] != 'f') {
        LOG_DEBUG("Invalid option passed: %c\n", argv[1][1]);
        sprintf(error_text, "option is invalid: %c", argv[1][1]);
        return CPLIB_ERR_ARG;
    }

    ret = cplib_read_file(argv[2], &iv);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to get initialization vector from file\n");
        strcpy(error_text, "Failed to read initialization vector");
        cplib_destroyable_put(*initialization_vector);
        return ret;
    }

    if (iv->taken != block_iteration_size) {
        LOG_DEBUG("Initialization vector must be of size: %zu\n", block_iteration_size);
        sprintf(error_text, "Initialization vector must be of size: %zu\n", block_iteration_size);
        cplib_destroyable_put(iv);
        return CPLIB_ERR_ARG;
    }

    *initialization_vector = iv;

    return CPLIB_ERR_SUCCESS;
}

int cbc_get_mode(int argc,
                 const char **argv,
                 enum cplib_proc_type process,
                 size_t block_iteration_size,
                 cplib_mode_base_t **mode,
                 cplib_block_padder_base_t **padder,
                 enum cplib_proc_type *effective_process) {
    CPLIB_UNUSED_PARAM(argc);
    CPLIB_UNUSED_PARAM(argv);

    int ret;
    cplib_mem_chunk_t *initialization_vector = NULL;

    *effective_process = process;

    if (process != CPLIB_PROC_ENCRYPT && process != CPLIB_PROC_DECRYPT) {
        LOG_DEBUG("Invalid process type\n");
        strcpy(error_text, "Invalid process type");
        return CPLIB_ERR_ARG;
    }

    ret = cbc_mode_parse_args(argc, argv, block_iteration_size, &initialization_vector);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to parse CBC mode args\n");
        goto error_cleanup;
    }

    ret = cbc_mode_allocate(initialization_vector, process, (cbc_mode_t **) mode);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to allocate CBC mode\n");
        goto error_cleanup;
    }

    *padder = cplib_pkcs5_padder_new(process);
    if (*padder == NULL) {
        LOG_DEBUG("Failed to allocate padder\n");
        ret = CPLIB_ERR_MEM;
        goto error_cleanup;
    }

    return CPLIB_ERR_SUCCESS;

    error_cleanup:
    CPLIB_PUT_IF_EXISTS(initialization_vector);
    CPLIB_PUT_IF_EXISTS(mode);
    CPLIB_PUT_IF_EXISTS(*padder);
    return ret;
}

static size_t supported_key_sizes[] = {KCRYPT_ANY_KEY_SIZE};
static const char *help_text = "Usage: -- " KCRYPT_MODE_CBC " < -i <initialization vector> | -f <initialization vector file> >\n";

int cbc_destroy(void *unused) {
    CPLIB_UNUSED_PARAM(unused);
    CPLIB_PUT_IF_EXISTS(block_manipulator);
    return CPLIB_ERR_SUCCESS;
}

char *get_error_text(kcrypt_mode_module_api_t *self) {
    CPLIB_UNUSED_PARAM(self);
    return error_text;
}


int kcrypt_lib_init(void *lib_api) {
    kcrypt_mode_module_api_t *api = (kcrypt_mode_module_api_t *) lib_api;
    if (api->struct_size == sizeof(kcrypt_mode_module_api_t)) {
        api->supported_key_sizes = supported_key_sizes;
        api->supported_key_sizes_count = 1;
        api->get_mode = cbc_get_mode;
        api->destroy = cbc_destroy;
    }
    api->help_text = help_text;
    api->get_error_text = (error_text_f) get_error_text;

    return CPLIB_ERR_SUCCESS;
}
