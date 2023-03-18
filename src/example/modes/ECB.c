/**
 * Karel Chanivecky 2023.
 */

#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"

size_t ECB_get_output_key_size(size_t input_key_size) {
    return input_key_size;
}

int ECB_get_mode(int argc,
                 const char **argv,
                 enum cplib_proc_type process,
                 cplib_mode_base_t **mode,
                 cplib_block_padder_base_t **padder) {
    CPLIB_UNUSED_PARAM(argc);
    CPLIB_UNUSED_PARAM(argv);

    *mode = NULL;
    if (process != CPLIB_PROC_ENCRYPT && process != CPLIB_PROC_DECRYPT) {
        LOG_DEBUG("Invalid process type\n");
        return CPLIB_ERR_ARG;
    }

    *padder = cplib_pkcs5_padder_new(process);
    if (*padder == NULL) {
        LOG_DEBUG("Failed to allocate padder\n");
        return CPLIB_ERR_MEM;
    }

    return CPLIB_ERR_SUCCESS;
}

static size_t supported_key_sizes[] = {KCRYPT_ANY_KEY_SIZE};
static const char * help_text = "Usage: -- " KCRYPT_MODE_ECB "\nSupported key sizes: [" KCRYPT_ANY_KEY_SIZE_STR "]";

int ECB_destroy(void * unused) {
    CPLIB_UNUSED_PARAM(unused);
    return CPLIB_ERR_SUCCESS;
}

int kcrypt_lib_api_init(void *lib_api) {
    kcrypt_mode_module_api_t * api = (kcrypt_mode_module_api_t *)lib_api;

    api->supported_key_sizes = supported_key_sizes;
    api->supported_key_sizes_count = 1;
    api->get_output_key_size = ECB_get_output_key_size;
    api->get_mode = ECB_get_mode;
    api->help_text = help_text;
    api->struct_size = sizeof(kcrypt_mode_module_api_t);
    api->destroy = ECB_destroy;
    return CPLIB_ERR_SUCCESS;
}
