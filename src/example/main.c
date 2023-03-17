#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"
#include "kcrypt_utils.h"


struct arg_options_t {
    char *exe_name;
    char *cipher;
    char *mode;
    char *key;
    char *key_path;
    char *output_path;
    char *input_path;
    char *message;
    int remaining_argc;
    char **remaining_argv;
};

typedef struct arg_options_t arg_options_t;

struct kcrypt_context_t {
    size_t input_key_size;
    size_t effective_key_size;
    cplib_mem_chunk_t *key;
    cplib_writer_base_t *writer;
    cplib_cipher_base_t *cipher;
    cplib_block_padder_base_t *padder;
    cplib_block_iterator_base_t *block_iterator;
    size_t block_size;
    cplib_mode_base_t *mode;
    kcrypt_cipher_module_api_t *cipher_module_api;
    kcrypt_mode_module_api_t *mode_module_api;
    void *cipher_lib_handle;
    void *mode_lib_handle;
    int cipher_argc;
    int mode_argc;
    char **cipher_argv;
    char **mode_argv;
};

typedef struct kcrypt_context_t kcrypt_context_t;

static arg_options_t options = {0};
static kcrypt_context_t kcrypt_context = {0};
static char *exe_name = NULL;

int run_kcrypt(
        cplib_mem_chunk_t *key,
        cplib_key_provider_factory_base_t *key_provider_factory,
        cplib_block_iterator_base_t *block_iterator,
        cplib_writer_base_t *writer,
        cplib_mode_base_t *mode,
        cplib_cipher_base_t *cipher,
        cplib_block_padder_base_t *block_padder
) {
    int ret;
    cplib_cipher_driver_t *cipher_driver = NULL;
    cplib_cipher_factory_base_t *cipher_factory = NULL;
    cplib_key_provider_base_t *key_provider = NULL;


    ret = key_provider->initialize(key_provider, key);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize key provider\n");
        goto cleanup;
    }

    cipher_factory = cipher_get_cipher_factory(process);
    if (!cipher_factory) {
        LOG_MSG("Failed to create cipher factory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    cipher_driver = cplib_cipher_driver_new();
    if (!cipher_driver) {
        LOG_MSG("Failed to create cipher driver\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    CPLIB_HOLD_IF_EXISTS(cipher_factory);
    CPLIB_HOLD_IF_EXISTS(key_provider);


    cipher_driver->writer = writer;
    cipher_driver->cipher_factory = cipher_factory;
    cipher_driver->key_provider = key_provider;
    cipher_driver->block_padder = block_padder;
    cipher_driver->block_iterator = block_iterator;
    cipher_driver->mode = mode;
    cipher_driver->block_size = key->taken * cipher_block_to_key_ratio();

    cipher_driver->run(cipher_driver);

    cleanup:

    CPLIB_PUT_IF_EXISTS(cipher_driver);
    CPLIB_PUT_IF_EXISTS(key_provider);
    CPLIB_PUT_IF_EXISTS(cipher_factory);

    return ret;
}

int get_key(char *key_path, cplib_mem_chunk_t **key) {
    ssize_t ret;
    int fd;
    struct stat key_stat;
    LOG_DEBUG("Getting key from file %s\n", key_path);

    fd = open(key_path, O_RDONLY);
    if (fd == -1) {
        LOG_MSG("Failed to open %s due to error: %s\n", key_path, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    ret = fstat(fd, &key_stat);
    if (ret == -1) {
        LOG_MSG("Failed to stat %s due to error: %s\n", key_path, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    *key = cplib_allocate_mem_chunk(key_stat.st_size);
    if (!*key) {
        LOG_MSG("Failed to allocate memory for key\n");
        return CPLIB_ERR_MEM;
    }

    LOG_VERBOSE("Key size: %ld\n", key_stat.st_size);
    ret = read(fd, (*key)->mem, key_stat.st_size);
    if (ret == -1) {
        LOG_MSG("Failed to read %s due to error: %s\n", key_path, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    if (ret != key_stat.st_size) {
        LOG_MSG("Failed to read key from file.\n");
    }

    (*key)->taken = key_stat.st_size;

    return CPLIB_ERR_SUCCESS;
}

int init_key(arg_options_t *options) {

}

int get_block_iterator(int input_fd, cplib_mem_chunk_t *data, size_t iterated_size,
                       cplib_block_iterator_base_t **block_iterator) {
    size_t buffer_size;

#ifdef CPLIB_DEBUG
    buffer_size = KCRYPT_FILE_BUFFER_SIZE < iterated_size ? iterated_size : KCRYPT_FILE_BUFFER_SIZE;
#else
    buffer_size = KCRYPT_FILE_BUFFER_SIZE;
#endif

    if (data) {
        *block_iterator = cplib_allocated_block_iterator_new(data, iterated_size);
        if (!*block_iterator) {
            LOG_MSG("Failed to create block iterator\n");
            return CPLIB_ERR_MEM;
        }

        return CPLIB_ERR_SUCCESS;
    }

    if (input_fd != CPLIB_INVALID_FD) {
        *block_iterator = cplib_file_block_iterator_new(input_fd, iterated_size, buffer_size);
        if (!*block_iterator) {
            LOG_MSG("Failed to create block iterator\n");
            return CPLIB_ERR_MEM;
        }

        return CPLIB_ERR_SUCCESS;
    }

    LOG_MSG("Must provide either data or input_fd\n");
    return CPLIB_ERR_ARG;
}


void print_usage(char *exe_name) {
    fprintf(stderr,
            "Usage:\n"
            "%s [-k <key> | -l <key file>] [-o <output file>] [-f <input file> | -m <message>] [-- MODE <mode options>] [-- CIPHER <cipher options> ]\n"
            "if -o is not provided writes to stdout\n"
            "if -f or -m is not provided reads message from stdin\n"
            "\n"
            "%s help <cipher | mode>\n"
            "list available ciphers or modes\n"
            "%s help < cipher <cipher name> | mode <mode name> >\n", exe_name, exe_name, exe_name);
}

int print_available_libs(char *lib_type_name) {
    cplib_mem_chunk_t **available_libs;
    unsigned int available_libs_count;
    int ret;
    char *lib_name;

    ret = kcrypt_get_available_shared_libs(lib_type_name, &available_libs, &available_libs_count);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get available %s. code: %d\n", lib_type_name, ret);
        return ret;
    }

    LOG_MSG("Available %s: [", lib_type_name);
    for (unsigned int i = 0; i < available_libs_count; i++) {
        if (i > 0) {
            LOG_MSG(", ");
        }
        lib_name = available_libs[i]->mem;

        for (size_t j = available_libs[i]->size - 1; j > 0; j--) {
            if (lib_name[j] == '.') {
                lib_name[j] = '\0';
            }
        }

        LOG_MSG("%s", lib_name);
        CPLIB_PUT_IF_EXISTS(available_libs[i]);
    }

    cplib_free(available_libs);

    LOG_MSG("]\n");
    return CPLIB_ERR_SUCCESS;
}

int validate_mode_selection(const char *chosen_mode, char **accepted_modes, unsigned int accepted_modes_count) {
    /*
     * The cipher will give a list of mode acronyms. However, there may exist more than one implementation
     * for each mode. To accommodate this, we define that we will only evaluate until the next dot.
     * Each available mode will always have at least one dot, given that the file extension is ".so".
     */
    size_t chosen_mode_len;
    cplib_mem_chunk_t *augmented_chosen_mode;

    chosen_mode_len = strlen(chosen_mode);
    augmented_chosen_mode = cplib_allocate_mem_chunk(chosen_mode_len + 2);
    if (augmented_chosen_mode == NULL) {
        LOG_MSG("Failed to allocate memory for chosen mode\n");
        return CPLIB_ERR_MEM;
    }

    augmented_chosen_mode->append(augmented_chosen_mode, chosen_mode, chosen_mode_len);
    augmented_chosen_mode->append(augmented_chosen_mode, ".\0", 2);

    if (kcrypt_n_match_str((char **) &chosen_mode,
                           1, accepted_modes,
                           accepted_modes_count,
                           chosen_mode_len)) {
        return CPLIB_ERR_SUCCESS;
    }

    return CPLIB_ERR_ARG;
}

int print_lib_usage(char *lib_type, char *lib_name) {
    void *lib_handle;
    size_t lib_name_len;
    size_t full_lib_name_len;
    size_t lib_path_len;
    size_t lib_type_len;
    cplib_mem_chunk_t *lib_path;
    int ret;
    kcrypt_shared_module_api_t shared_module_api = {0};
    shared_module_api.struct_size = sizeof(shared_module_api);

    lib_name_len = strlen(lib_name);
    full_lib_name_len = lib_name_len + 3; // lib_name + ".so
    lib_type_len = strlen(lib_type);
    lib_path_len = full_lib_name_len + lib_type_len;

    lib_path = cplib_allocate_mem_chunk(sizeof(char) * lib_path_len + 2); // null byte and '/' for path
    if (!lib_path) {
        LOG_MSG("Failed to allocate memory for lib path\n");
        return CPLIB_ERR_MEM;
    }

    lib_path->append(lib_path, lib_type, lib_type_len);
    lib_path->append(lib_path, "/", 1);
    lib_path->append(lib_path, lib_name, lib_name_len);
    lib_path->append(lib_path, ".so\0", 4);

    ret = kcrypt_init_module_api(lib_path->mem, &shared_module_api, lib_handle);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize lib %s\n", lib_name);
        return ret;
    }

    LOG_MSG("%s: %s\n%s\n", lib_type, lib_name, shared_module_api.help_text);

    dlclose(lib_handle);
    lib_path->destroy(lib_path);
    return CPLIB_ERR_SUCCESS;
}


int find_module_args(char *header, int argc, char **argv, int *module_argc, char ***module_argv) {

    for (int i = 0; i < argc; i++) {
        if (strncmp(header, argv[i], strlen(header)) == 0) {
            // module argv starts on next arg from the header
            *module_argc = argc - i - 1;
            *module_argv = argv + i + 1;
            return CPLIB_ERR_SUCCESS;
        }
    }

    return CPLIB_ERR_ARG;
}

int get_module(const char *lib_dir, const char *lib_name, kcrypt_shared_module_api_t *module_api) {
    int ret;

    cplib_mem_chunk_t *lib_path;

    ret = kcrypt_make_lib_path(lib_dir, lib_name, &lib_path);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to make lib path for cipher %s\n", lib_name);
        return ret;
    }

    ret = kcrypt_init_module_api(lib_path->mem,
                                 (kcrypt_shared_module_api_t *) module_api,
                                 &kcrypt_context.cipher_lib_handle);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize lib %s\n", lib_name);
        return ret;
    }

    lib_path->destroy(lib_path);
    lib_path = NULL;

    return CPLIB_ERR_SUCCESS;
}

int load_apis(void) {
    int ret;
    kcrypt_context_t *ctx = &kcrypt_context;

    ret = get_module(KCRYPT_CIPHER_LIB_DIR,
                     options.cipher,
                     (kcrypt_shared_module_api_t *) ctx->cipher_module_api);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get cipher module %s\n", options.cipher);
        return ret;
    }

    if (ctx->cipher_module_api->mandatory_mode) {
        if (options.mode
            &&
            strncmp(ctx->cipher_module_api->mandatory_mode,
                    options.mode,
                    strlen(ctx->cipher_module_api->mandatory_mode)) != 0) {
            LOG_MSG("Mode %s specified, but chosen cipher mandates a different mode %s."
                    " Not allowed to choose mode\n", options.mode, ctx->cipher_module_api->mandatory_mode);
            return CPLIB_ERR_ARG;
        }

        LOG_DEBUG("Using mode mandated by cipher: %s\n", options.mode);
        options.mode = ctx->cipher_module_api->mandatory_mode;
    }

    ctx->input_key_size = ctx->key->taken;
    ctx->effective_key_size = ctx->key->taken;

    ret = get_module(KCRYPT_MODE_LIB_DIR,
                     options.mode,
                     (kcrypt_shared_module_api_t *) ctx->mode_module_api);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get mode module %s\n", options.mode);
        return ret;
    }

    return CPLIB_ERR_SUCCESS;
}

void set_module_args(void) {

    find_module_args(KCRYPT_CLI_CIPHER_ARGS_HEADER,
                     options.remaining_argc,
                     options.remaining_argv,
                     &kcrypt_context.cipher_argc,
                     &kcrypt_context.cipher_argv);

    find_module_args(KCRYPT_CLI_MODE_ARGS_HEADER,
                     options.remaining_argc,
                     options.remaining_argv,
                     &kcrypt_context.mode_argc,
                     &kcrypt_context.mode_argv);
}


int validate_key_size(void) {
    int ret;


    if (!kcrypt_match_sizes(ctx->input_key_size,
                            ctx->mode_module_api->supported_key_sizes,
                            ctx->mode_module_api->supported_key_sizes_count)) {
        LOG_MSG("Mode does not support given key size\n"
                "Mode usage: %s\n", ctx->mode_module_api->help_text);
        return CPLIB_ERR_KEY_SIZE;
    }

    kcrypt_context.effective_key_size = ctx->mode_module_api->get_output_key_size(ctx->input_key_size);

    LOG_DEBUG("Effective key size: %zu\n", ctx->effective_key_size);

    if (!kcrypt_match_sizes(ctx->effective_key_size,
                            ctx->cipher_module_api->supported_key_sizes,
                            ctx->cipher_module_api->supported_key_sizes_count)) {
        LOG_MSG("Cipher does not support the effective key size %zu. "
                "The effective key size may be affected by the mode\n", ctx->effective_key_size);
        return CPLIB_ERR_KEY_SIZE;
    }

    return CPLIB_ERR_SUCCESS;
}

int process_parsed_args(void) {
    int ret = CPLIB_ERR_SUCCESS;
    int input_fd = CPLIB_INVALID_FD;
    int output_fd = CPLIB_INVALID_FD;
    size_t block_to_key_ratio = 0;
    cplib_mem_chunk_t *message = NULL;

    if (options.message) {
        message = cplib_mem_chunk_str_new(options.message);
        message->taken--;
    }

    if (!options.key_path && !options.key) {
        print_usage(exe_name);
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    if (!options.output_path) {
        LOG_DEBUG("Output directed to stdout\n");
        output_fd = STDOUT_FILENO;
    } else {
        output_fd = open(options.output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd == -1) {
            LOG_MSG("Failed to open output file %s\n", options.output_path);
            ret = CPLIB_ERR_FILE;
            goto error_cleanup;
        }
    }

    if (options.key_path) {
        ret = get_key(options.key_path, &kcrypt_context.key);
        if (ret != CPLIB_ERR_SUCCESS) {
            goto error_cleanup;
        }
    }

    if (options.key) {
        kcrypt_context.key = cplib_mem_chunk_new(options.key, strlen(options.key));
        if (!kcrypt_context.key) {
            LOG_MSG("Failed to allocate memory for key\n");
            ret = CPLIB_ERR_MEM;
            goto error_cleanup;
        }
    }

    ret = load_apis();
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to load APIs\n");
        return ret;
    }

    ret = validate_key_size();
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to validate key size\n");
        return ret;
    }

    kcrypt_context.writer = (cplib_writer_base_t *) cplib_file_writer_new(output_fd);
    if (!kcrypt_context.writer) {
        LOG_MSG("Failed to create writer\n");
        ret = CPLIB_ERR_MEM;
        goto error_cleanup;
    }

    if (options.input_path) {
        input_fd = open(options.input_path, O_RDONLY);
        if (input_fd == -1) {
            LOG_MSG("Failed to open input file %s\n", options.input_path);
            ret = CPLIB_ERR_FILE;
            goto error_cleanup;
        }
    } else if (!options.message) {
        LOG_DEBUG("Reading message from stdin\n");
        input_fd = STDIN_FILENO;
    }

    block_to_key_ratio = kcrypt_context.cipher_module_api->block_to_key_size_ratio;
    kcrypt_context.block_size = block_to_key_ratio * kcrypt_context.effective_key_size;

    // init cipher
    if (!options.cipher) {

    }

    if (options.mode) {

    }

    // init mode


    ret = get_block_iterator(input_fd,
                             message,
                             kcrypt_context.effective_key_size,
                             &kcrypt_context.block_iterator);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get block iterator. code: %d\n", ret);
        goto error_cleanup;
    }
// TODO HERE!!!!!!!!
    *padder = cplib_pkcs5_padder_new(*process);
    if (!*padder) {
        LOG_MSG("Failed to allocate padder\n");
        ret = CPLIB_ERR_MEM;
        goto error_cleanup;
    }

    LOG_DEBUG("Arguments parsed successfully\n");
    ret = CPLIB_ERR_SUCCESS;
    return CPLIB_ERR_SUCCESS;

    error_cleanup:
    CPLIB_PUT_IF_EXISTS(*key);
    CPLIB_PUT_IF_EXISTS(*block_iterator);
    CPLIB_PUT_IF_EXISTS(*writer);
    CPLIB_PUT_IF_EXISTS(*mode);
    CPLIB_PUT_IF_EXISTS(*padder);

    return ret;
}

void init_options(void) {
    options.cipher = NULL;
    options.mode = KCRYPT_MODE_ECB;
    options.key = NULL;
    options.key_path = NULL;
    options.output_path = NULL;
    options.input_path = NULL;
    options.message = NULL;
    options.remaining_argc = 0;
    options.remaining_argv = NULL;
}


int parse_args(int argc, char **argv) {

    int opt;

    LOG_DEBUG("Parsing arguments\n");
    /*
     * -k key
     * -l key file
     * -o output file
     * -f input file
     * -m message
     * -d mode
     *  -- CIPHER ... cipher args
     *  -- MODE... mode args
     */
    exe_name = argv[0];
    if (argc < 3) {
        print_usage(exe_name);
        return CPLIB_ERR_ARG;
    }

    if (strncmp(argv[1], "help", 4) == 0) {

        if (strncmp(argv[2], "cipher", 6) == 0) {
            if (argc == 3) {
                print_available_libs(KCRYPT_CIPHER_LIB_DIR);
            } else {
                print_lib_usage(KCRYPT_CIPHER_LIB_DIR, argv[3]);
            }

            return CPLIB_ERR_ARG;
        } else if (strncmp(argv[2], "mode", 4) == 0) {

            if (argc == 3) {
                print_available_libs(KCRYPT_MODE_LIB_DIR);
            } else {
                print_lib_usage(KCRYPT_MODE_LIB_DIR, argv[3]);
            }

            return CPLIB_ERR_ARG;
        }

        print_usage(exe_name);
        return CPLIB_ERR_ARG;
    }

    options.cipher = argv[1];

    while ((opt = getopt(argc, argv, "k:l:o:f:m:c:d:")) != -1) {
        switch (opt) {
            case 'd':
                options.mode = optarg;
                break;
            case 'f':
                if (options.message) {
                    LOG_MSG("Provide either -f, -m or neither\n");
                    print_usage(exe_name);
                    return CPLIB_ERR_ARG;
                }

                options.input_path = optarg;
                break;
            case 'k':
                if (options.key_path) {
                    LOG_MSG("Provide either -k or -l\n");
                    print_usage(exe_name);
                    return CPLIB_ERR_ARG;
                }
                options.key = optarg;
                break;
            case 'l':
                if (options.key) {
                    LOG_MSG("Provide either -k or -l\n");
                    print_usage(exe_name);
                    return CPLIB_ERR_ARG;
                }
                options.key_path = optarg;
                break;
            case 'o':
                options.output_path = optarg;
                break;
            case 'm':
                if (options.input_path) {
                    LOG_MSG("Provide either -f, -m or neither\n");
                    print_usage(exe_name);
                    return CPLIB_ERR_ARG;
                }
                options.message = optarg;
                break;
            default:
                LOG_MSG("Unknown arg: %c\n", opt);
                print_usage(exe_name);
                return CPLIB_ERR_ARG;
        }

    }

    LOG_DEBUG("Arguments parsed:"
              "options->cipher: %s\n"
              "options->input_path: %s\n"
              "options->key_path: %s\n"
              "options->key: %s\n"
              "options->output_path: %s\n"
              "options->message: %s\n"
              "options->mode %s\n",
              options.cipher,
              options.input_path,
              options.key_path,
              options.key,
              options.output_path,
              options.message,
              options.mode);

    if (optind >= argc) {
        LOG_MSG("Missing option argument\n");
        print_usage(exe_name);
        return CPLIB_ERR_ARG;
    }

    if (optind == -1) {
        return CPLIB_ERR_SUCCESS;
    }
    // optind is pointing at the next arg. Hence, the actual number of args consumed is one less than optind.
    options.remaining_argc = argc - optind + 1;
    options.remaining_argv = argv + optind;

    set_module_args();
    return CPLIB_ERR_SUCCESS;
}


int main(int argc, char **argv) {
    int ret;

    cplib_mem_chunk_t *key = NULL;
    cplib_block_iterator_base_t *block_iterator = NULL;
    cplib_mode_base_t *mode = NULL;
    cplib_block_padder_base_t *padder = NULL;
    cplib_writer_base_t *writer = NULL;
    cplib_cipher_base_t *cipher = NULL;
    cplib_key_provider_factory_base_t *key_provider_factory;

    ret = parse_args(argc, argv);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to parse arguments. code: %d\n", ret);
        goto cleanup;
    }

    ret = process_parsed_args();

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to process arguments. code: %d\n", ret);
        goto cleanup;
    }

    CPLIB_HOLD_IF_EXISTS(key_provider_factory);
    CPLIB_HOLD_IF_EXISTS(block_iterator);
    CPLIB_HOLD_IF_EXISTS(mode);
    CPLIB_HOLD_IF_EXISTS(cipher);
    CPLIB_HOLD_IF_EXISTS(padder);
    CPLIB_HOLD_IF_EXISTS(writer);

    ret = run_kcrypt(
            key,
            key_provider_factory,
            block_iterator,
            writer,
            mode,
            cipher,
            padder);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("KCrypt failed. Code: %d\n", ret);
        goto cleanup;
    }

    cleanup:

    CPLIB_PUT_IF_EXISTS(key);
    CPLIB_PUT_IF_EXISTS(key_provider_factory);
    CPLIB_PUT_IF_EXISTS(block_iterator);
    CPLIB_PUT_IF_EXISTS(mode);
    CPLIB_PUT_IF_EXISTS(cipher);
    CPLIB_PUT_IF_EXISTS(padder);
    CPLIB_PUT_IF_EXISTS(writer);

    if (kcrypt_context.mode_lib_handle) {
        dlclose(kcrypt_context.mode_lib_handle);
    }

    if (kcrypt_context.cipher_lib_handle) {
        dlclose(kcrypt_context.cipher_lib_handle);
    }

    if (ret == CPLIB_ERR_SUCCESS) {
        return EXIT_SUCCESS;
    }

    return ret;
}
