/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_KCRYPT_H
#define SOURCES_KCRYPT_H

#include "ciphrameworklib.h"

#ifdef CPLIB_DEBUG
    #define KCRYPT_FILE_BUFFER_SIZE 10
#else
    #define KCRYPT_FILE_BUFFER_SIZE 30000000 // 10MB
#endif


#define KCRYPT_LIB_MODULE_INIT_FUNCTION_NAME "kcrypt_lib_init"


struct kcrypt_shared_module_api_t {
    cplib_destroyable_t;
    const char *help_text;
    size_t struct_size;
};

typedef struct kcrypt_shared_module_api_t kcrypt_shared_module_api_t;


typedef int (*kcrypt_get_cipher_f)(
        int argc,
        const char **argv,
        enum cplib_proc_type process,
        cplib_cipher_factory_base_t **cipher_factory,
        cplib_key_provider_base_t **key_provider);


struct kcrypt_cipher_module_api_t {
    kcrypt_shared_module_api_t;
    size_t *supported_key_sizes;
    unsigned int supported_key_sizes_count;
    size_t block_to_key_size_ratio;
    const char **supported_modes;
    char *mandatory_mode;
    unsigned int supported_mode_count;
    kcrypt_get_cipher_f get_cipher;
};

typedef struct kcrypt_cipher_module_api_t kcrypt_cipher_module_api_t;

typedef size_t (*kcrypt_get_output_key_size_f)(size_t input_key_size);

typedef int (*kcrypt_get_mode_f)(int argc,
                                 const char **argv,
                                 enum cplib_proc_type process,
                                 cplib_mode_base_t **mode,
                                 cplib_block_padder_base_t **padder);

struct kcrypt_mode_module_api_t {
    kcrypt_shared_module_api_t;
    size_t *supported_key_sizes;
    unsigned int supported_key_sizes_count;
    kcrypt_get_output_key_size_f get_output_key_size;
    kcrypt_get_mode_f get_mode;
};

typedef struct kcrypt_mode_module_api_t kcrypt_mode_module_api_t;

typedef int(*kcrypt_lib_api_init_f)(void *lib_api);

// Matches any mode. Place at the start of supported modes.
#define KCRYPT_MODE_ANY "ANY"
// common modes
#define KCRYPT_MODE_ECB "ECB"
#define KCRYPT_MODE_CBC "CBC"
#define KCRYPT_MODE_CTR "CTR"
#define KCRYPT_MODE_OFB "OFB"
#define KCRYPT_MODE_CFB "CFB"

// Matches any key size. Place at the start of supported key sizes.
#define KCRYPT_ANY_KEY_SIZE 0
#define KCRYPT_ANY_KEY_SIZE_STR "0 (Any size)"

#define KCRYPT_CLI_MODE_ARGS_HEADER "MODE"
#define KCRYPT_CLI_CIPHER_ARGS_HEADER "CIPHER"

#define KCRYPT_CIPHER_LIB_DIR "ciphers"
#define KCRYPT_MODE_LIB_DIR "modes"

#endif //SOURCES_KCRYPT_H
