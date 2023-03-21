/**
 * Karel Chanivecky 2023.
 */

#include <string.h>
#include <getopt.h>
#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"

static char error_text[KCRYPT_ERROR_TEXT_MAX_LENGTH] = {0};

typedef uint32_t counter_size_t;

struct ctr_mode_t {
    cplib_mode_base_t;
    cplib_mem_chunk_t *counter;
};

typedef struct ctr_mode_t ctr_mode_t;


int ctr_mode_get_counter(ctr_mode_t *self,
                         cplib_mem_chunk_t *data,
                         cplib_mem_chunk_t *key,
                         enum cplib_block_position position,
                         cplib_mem_chunk_t **out) {
    CPLIB_UNUSED_PARAM(data);
    CPLIB_UNUSED_PARAM(key);
    CPLIB_UNUSED_PARAM(position);
    cplib_mem_chunk_t *counter_chunk = NULL;
    cplib_mem_chunk_t *o = NULL;
    uint8_t *counter_start_ptr = NULL;


    counter_chunk = self->counter;
    counter_start_ptr = ((uint8_t *) counter_chunk->mem) + (counter_chunk->taken - sizeof(counter_size_t));
    LOG_VERBOSE("Counter incrementing from %du\n", *(counter_size_t *) counter_start_ptr);

    if (*out == NULL) {
        *out = cplib_allocate_mem_chunk(counter_chunk->taken);
    }

    if (!*out) {
        LOG_DEBUG("Failed to allocate memory for output block\n");
        strcpy(error_text, "Out of memory");
        return CPLIB_ERR_MEM;
    }

    o = *out;

    if (o->size < counter_chunk->taken) {
        LOG_DEBUG("Output chunk is too small\n");
        strcpy(error_text, "Application error");
        return CPLIB_ERR_ARG;
    }

    o->taken = 0;
    o->append(o, counter_chunk->mem, counter_chunk->taken - sizeof(counter_size_t));
    o->append(o, counter_start_ptr, sizeof(counter_size_t));

    (*(counter_size_t *) counter_start_ptr)++;

    return CPLIB_ERR_SUCCESS;
}

int ctr_mode_make_ciphertext(ctr_mode_t *self,
                             cplib_mem_chunk_t *processed,
                             cplib_mem_chunk_t *input_message,
                             cplib_mem_chunk_t *key,
                             enum cplib_block_position position,
                             cplib_mem_chunk_t **out) {
    CPLIB_UNUSED_PARAM(self);
    CPLIB_UNUSED_PARAM(input_message);
    CPLIB_UNUSED_PARAM(key);
    CPLIB_UNUSED_PARAM(position);

    uint8_t ct;
    cplib_mem_chunk_t *o = NULL;
    uint8_t *input_mem = NULL;
    uint8_t *processed_mem = NULL;


    if (*out == NULL) {
        *out = cplib_allocate_mem_chunk(input_message->taken);
    }

    if (!*out) {
        LOG_DEBUG("Failed to allocate memory for output block\n");
        strcpy(error_text, "Out of memory");
        return CPLIB_ERR_MEM;
    }

    o = *out;

    if (o->size < input_message->taken) {
        LOG_DEBUG("Output chunk is too small\n");
        strcpy(error_text, "Application error");
        return CPLIB_ERR_ARG;
    }

    if (processed->taken < input_message->taken) {
        LOG_DEBUG("Did not produce a big enough intermediate ciphertext\n");
        strcpy(error_text, "Application error");
        return CPLIB_ERR_ARG;
    }

    o->taken = 0;
    input_mem = input_message->mem;
    processed_mem = processed->mem;
    for (size_t i = 0; i < input_message->taken; i++) {
        ct = input_mem[i] ^ processed_mem[i];
        o->append(o, &ct, 1);
    }

    return CPLIB_ERR_SUCCESS;
}


int ctr_mode_destroy(ctr_mode_t *self) {
    CPLIB_PUT_IF_EXISTS(self->counter);
    return cplib_mode_base_destroy((cplib_mode_base_t *) self);
}

int ctr_mode_allocate(cplib_mem_chunk_t *initialization_vector, counter_size_t counter_start, ctr_mode_t **mode) {
    cplib_mem_chunk_t *counter = NULL;

    *mode = (ctr_mode_t *) cplib_mode_base_new(sizeof(ctr_mode_t),
                                               (cplib_mode_pre_transform_f) ctr_mode_get_counter,
                                               (cplib_mode_post_transform_f) ctr_mode_make_ciphertext);
    if (!*mode) {
        LOG_DEBUG("Failed to allocate memory for mode.\n");
        strcpy(error_text, "Out of memory\n");
        return CPLIB_ERR_MEM;
    }

    counter = cplib_allocate_mem_chunk(initialization_vector->taken + sizeof(counter_size_t));
    if (!counter) {
        LOG_DEBUG("Failed to allocate memory for mode counter.\n");
        strcpy(error_text, "Out of memory\n");
        cplib_destroyable_put(*mode);
        return CPLIB_ERR_MEM;
    }

    counter->append(counter, initialization_vector->mem, initialization_vector->taken);
    counter->append(counter, &counter_start, sizeof(counter_size_t));

    (*mode)->counter = counter;
    (*mode)->destroy = (cplib_independent_mutator_f) ctr_mode_destroy;

    CPLIB_PUT_IF_EXISTS(initialization_vector);

    return CPLIB_ERR_SUCCESS;
}

int ctr_mode_parse_args(int argc,
                        char **argv,
                        size_t block_iteration_size,
                        counter_size_t *counter_start_ptr,
                        cplib_mem_chunk_t **initialization_vector) {
    int ret;
    int opt;
    unsigned long long counter_start;
    size_t expected_iv_size;
    char *counter_start_str = NULL;
    cplib_mem_chunk_t *iv = NULL;

    expected_iv_size = block_iteration_size - sizeof(counter_size_t);

    optind = 1;
    while ((opt = getopt(argc, argv, "c:i:f:")) != -1) {
        switch (opt) {
            case 'i':
                if (iv) {
                    LOG_DEBUG("Found initialization vector in cli args, but already parsed from file\n");
                    strcpy(error_text, "Passed initialization vector in cli args and file");
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }

                LOG_DEBUG("Getting initialization vector from cli args\n");
                iv = cplib_mem_chunk_str_new(argv[2]);
                if (!iv) {
                    LOG_DEBUG("Failed to allocate initialization vector\n");
                    strcpy(error_text, "Out of memory");
                    ret = CPLIB_ERR_MEM;
                    goto error_cleanup;
                }
                iv->taken--; // str new allocates 1 extra byte for \0
                break;
            case 'f':
                if (iv) {
                    LOG_DEBUG("Found initialization vector file, but already parsed from cli args\n");
                    strcpy(error_text, "Passed initialization vector in cli args and file");
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                ret = cplib_read_file(argv[2], &iv);
                if (ret != CPLIB_ERR_SUCCESS) {
                    LOG_DEBUG("Failed to get initialization vector from file\n");
                    strcpy(error_text, "Failed to read initialization vector");
                    cplib_destroyable_put(*initialization_vector);
                    goto error_cleanup;
                }
                break;
            case 'c':
                LOG_DEBUG("Got counter start of %s", optarg);
                counter_start_str = optarg;
                break;
            default:
                LOG_DEBUG("Invalid option passed: %c\n", opt);
                sprintf(error_text, "option is invalid: %c", opt);
                ret = CPLIB_ERR_ARG;
                goto error_cleanup;
        }
    }

    if (!iv) {
        LOG_DEBUG("Did not provide initialization vector.\n");
        strcpy(error_text, "Did not provide initialization vector");
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    *initialization_vector = iv;

    if (!counter_start_str) {
        LOG_DEBUG("Did not provide counter start. Defaulting to 0\n");
        counter_start = 0;
    } else {
        ret = cplib_safe_strtoull(counter_start_str, NULL, 10, &counter_start);

        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to parse counter start from cli arg\n");
            strcpy(error_text, "Failed to parse mode counter start from cli arg\n");
            ret = CPLIB_ERR_ARG;
            goto error_cleanup;
        }
    }

    if (counter_start > UINT16_MAX) {
        LOG_DEBUG("Counter start must not be larger than %du\n", UINT16_MAX);
        sprintf(error_text, "Counter start must not be larger than %du", UINT16_MAX);
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    if (iv->taken < expected_iv_size) {
        LOG_DEBUG("Initialization vector must be of size: %zu\n", expected_iv_size);
        sprintf(error_text, "Initialization vector must be of size: %zu\n", expected_iv_size);
        cplib_destroyable_put(iv);
        *initialization_vector = NULL;
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    iv->taken = expected_iv_size; // make sure we only use what we need if passed a bigger iv

    *counter_start_ptr = counter_start;
    return CPLIB_ERR_SUCCESS;

    error_cleanup:
    CPLIB_PUT_IF_EXISTS(iv);
    *initialization_vector = NULL;
    return ret;
}

int ctr_get_mode(int argc,
                 const char **argv,
                 enum cplib_proc_type process,
                 size_t block_iteration_size,
                 cplib_mode_base_t **mode,
                 cplib_block_padder_base_t **padder,
                 enum cplib_proc_type *effective_process) {
    CPLIB_UNUSED_PARAM(argc);
    CPLIB_UNUSED_PARAM(argv);
    CPLIB_UNUSED_PARAM(process);

    int ret;
    counter_size_t counter_start;
    cplib_mem_chunk_t *initialization_vector = NULL;

    *effective_process = CPLIB_PROC_ENCRYPT;

    ret = ctr_mode_parse_args(argc, (char **) argv, block_iteration_size, &counter_start, &initialization_vector);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to parse CTR mode args\n");
        goto error_cleanup;
    }

    ret = ctr_mode_allocate(initialization_vector, counter_start, (ctr_mode_t **) mode);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to allocate CTR mode\n");
        goto error_cleanup;
    }

    *padder = NULL;

    return CPLIB_ERR_SUCCESS;

    error_cleanup:
    CPLIB_PUT_IF_EXISTS(initialization_vector);
    CPLIB_PUT_IF_EXISTS(mode);
    return ret;
}

static size_t supported_key_sizes[] = {KCRYPT_ANY_KEY_SIZE};
static const char *help_text = "Usage: -- " KCRYPT_MODE_CTR " < -i <initialization vector> | -f <initialization vector file> > [-c <counter starting value>]\n"
                               "\n"
                               "-c In decimal. If not provided, will use 0\n";

int ctr_destroy(void *unused) {
    CPLIB_UNUSED_PARAM(unused);
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
        api->get_mode = ctr_get_mode;
        api->destroy = ctr_destroy;
    }
    api->help_text = help_text;
    api->get_error_text = (error_text_f) get_error_text;

    return CPLIB_ERR_SUCCESS;
}
