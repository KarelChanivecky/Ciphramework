#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>

#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"
#include "kcrypt_utils.h"


struct arg_options_t {
    enum cplib_proc_type process;
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
    size_t key_size;
    cplib_mem_chunk_t *key;
    cplib_writer_base_t *writer;
    cplib_key_provider_base_t *key_provider;
    cplib_cipher_factory_base_t *cipher_factory;
    cplib_block_padder_base_t *padder;
    cplib_block_iterator_base_t *block_iterator;
    size_t block_size;
    cplib_mode_base_t *mode;
    kcrypt_cipher_module_api_t cipher_module_api;
    kcrypt_mode_module_api_t mode_module_api;
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

void init_context(void) {
    kcrypt_context.cipher_module_api.struct_size = sizeof(kcrypt_cipher_module_api_t);
    kcrypt_context.mode_module_api.struct_size = sizeof(kcrypt_mode_module_api_t);
}

int run_kcrypt(void) {
    int ret;
    cplib_cipher_driver_t *cipher_driver = NULL;

    cipher_driver = cplib_cipher_driver_new();
    if (!cipher_driver) {
        LOG_MSG("Failed to create cipher driver\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    CPLIB_HOLD_IF_EXISTS(kcrypt_context.cipher_factory);
    CPLIB_HOLD_IF_EXISTS(kcrypt_context.key_provider);


    cipher_driver->writer = kcrypt_context.writer;
    cipher_driver->cipher_factory = kcrypt_context.cipher_factory;
    cipher_driver->key_provider = kcrypt_context.key_provider;
    cipher_driver->block_padder = kcrypt_context.padder;
    cipher_driver->block_iterator = kcrypt_context.block_iterator;
    cipher_driver->mode = kcrypt_context.mode;
    cipher_driver->block_size = kcrypt_context.block_size;

    ret = cipher_driver->run(cipher_driver);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to process message\n");
    }

    cleanup:

    CPLIB_PUT_IF_EXISTS(cipher_driver);

    return ret;
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


void print_usage(void) {
    fprintf(stderr,
            "Usage:\n"
            "%s <cipher> <-p d | -p e> [-d <mode>] [-k <key> | -l <key file>] [-o <output file>] [-f <input file> | -m <message>] [-- MODE <mode options>] [-- CIPHER <cipher options> ]\n"
            "-p e for encryption\n"
            "-p d for encryption\n"
            "if -o is not provided writes to stdout\n"
            "if -f or -m is not provided reads message from stdin\n"
            "\n"
            "%s help <cipher | mode>\n"
            "list available ciphers or modes\n"
            "\n"
            "%s help < cipher <cipher name> | mode <mode name> >\n"
            "Get help on a specific cipher or mode\n"
            "\n"
            "Not all ciphers or modes need options. But for those that do, pass the options after the main options by\n"
            "adding '-- CIPHER' or '--MODE' respectively, following, add the options.\n",
            exe_name, exe_name, exe_name);
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

    if (strncmp(KCRYPT_MODE_ANY, accepted_modes[0], strlen(KCRYPT_MODE_ANY)) == 0) {
        return CPLIB_ERR_SUCCESS;
    }

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
    void *lib_handle = NULL;
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

    lib_path = cplib_allocate_mem_chunk(sizeof(char) * lib_path_len + 10); // null byte and '/' for path
    if (!lib_path) {
        LOG_MSG("Failed to allocate memory for lib path\n");
        return CPLIB_ERR_MEM;
    }

    lib_path->append(lib_path, "$ORIGIN/", 8);
    lib_path->append(lib_path, lib_type, lib_type_len);
    lib_path->append(lib_path, "/", 1);
    lib_path->append(lib_path, lib_name, lib_name_len);
    lib_path->append(lib_path, ".so\0", 4);

    ret = kcrypt_init_module_api(lib_path->mem, &shared_module_api, &lib_handle);
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
            *module_argc = argc - i;
            *module_argv = argv + i;
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
                     (kcrypt_shared_module_api_t *) &ctx->cipher_module_api);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get cipher module %s\n", options.cipher);
        return ret;
    }

    if (ctx->cipher_module_api.mandatory_mode) {
        if (options.mode
            &&
            strncmp(ctx->cipher_module_api.mandatory_mode,
                    options.mode,
                    strlen(ctx->cipher_module_api.mandatory_mode)) != 0) {
            LOG_MSG("Mode %s specified, but chosen cipher mandates a different mode %s."
                    " Not allowed to choose mode\n", options.mode, ctx->cipher_module_api.mandatory_mode);
            return CPLIB_ERR_ARG;
        }

        LOG_DEBUG("Using mode mandated by cipher: %s\n", options.mode);
        options.mode = ctx->cipher_module_api.mandatory_mode;
    }

    ret = validate_mode_selection(options.mode,
                                  (char **) ctx->cipher_module_api.supported_modes,
                                  ctx->cipher_module_api.supported_mode_count);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Chosen mode %s is not supported\n", options.mode);
        return ret;
    }

    ctx->key_size = ctx->key->taken;

    ret = get_module(KCRYPT_MODE_LIB_DIR,
                     options.mode,
                     (kcrypt_shared_module_api_t *) &ctx->mode_module_api);
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
    kcrypt_context_t *ctx = &kcrypt_context;

    if (ctx->mode_module_api.supported_key_sizes[0] != KCRYPT_ANY_KEY_SIZE
        && !kcrypt_match_sizes(ctx->key_size,
                               ctx->mode_module_api.supported_key_sizes,
                               ctx->mode_module_api.supported_key_sizes_count)) {
        LOG_MSG("Mode does not support given key size\n"
                "Mode usage: %s\n", ctx->mode_module_api.help_text);
        return CPLIB_ERR_KEY_SIZE;
    }

    if (kcrypt_context.cipher_module_api.supported_key_sizes[0] == KCRYPT_ANY_KEY_SIZE) {
        LOG_DEBUG("Cipher supports any key size\n");
        return CPLIB_ERR_SUCCESS;
    }

    if (!kcrypt_match_sizes(ctx->key_size,
                            ctx->cipher_module_api.supported_key_sizes,
                            ctx->cipher_module_api.supported_key_sizes_count)) {
        LOG_MSG("Cipher does not support the key size %zu. "
                "The effective key size may be affected by the mode\n", ctx->key_size);
        return CPLIB_ERR_KEY_SIZE;
    }

    LOG_DEBUG("Cipher supports key size of %zu\n", kcrypt_context.key_size);
    return CPLIB_ERR_SUCCESS;
}

int process_parsed_args(void) {
    int ret;
    int input_fd = CPLIB_INVALID_FD;
    int output_fd = CPLIB_INVALID_FD;
    size_t block_to_key_ratio;
    cplib_mem_chunk_t *message = NULL;
    enum cplib_proc_type effective_process;

    if (options.message) {
        message = cplib_mem_chunk_str_new(options.message);
        message->taken--;
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

    if (!message && input_fd == CPLIB_INVALID_FD) {
        LOG_MSG("Must provide a message file or message in cli arguments\n");
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    if (!options.key_path && !options.key) {
        print_usage();
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
        ret = cplib_read_file(options.key_path, &kcrypt_context.key);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("Failed to read key file %s\n", options.key_path);
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



    block_to_key_ratio = kcrypt_context.cipher_module_api.block_to_key_size_ratio;
    kcrypt_context.block_size = block_to_key_ratio * kcrypt_context.key_size;


    ret = get_block_iterator(input_fd,
                             message,
                             kcrypt_context.block_size,
                             &kcrypt_context.block_iterator);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get block iterator. code: %d\n", ret);
        goto error_cleanup;
    }


    ret = kcrypt_context.mode_module_api.get_mode(kcrypt_context.mode_argc,
                                                  (const char **) kcrypt_context.mode_argv,
                                                  options.process,
                                                  kcrypt_context.block_size,
                                                  &kcrypt_context.mode,
                                                  &kcrypt_context.padder,
                                                  &effective_process);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize mode\n");
        if (ret == CPLIB_ERR_ARG) {
            print_lib_usage(KCRYPT_MODE_LIB_DIR, options.mode);
        }
        goto error_cleanup;
    }

#ifdef CPLIB_DEBUG
    if (options.process != effective_process) {
        LOG_DEBUG("Mode forced process: %d\n", effective_process);
    }
#endif

    options.process = effective_process;

    ret = kcrypt_context.cipher_module_api.get_cipher(kcrypt_context.cipher_argc,
                                                      (const char **) kcrypt_context.cipher_argv,
                                                      options.process,
                                                      &kcrypt_context.cipher_factory,
                                                      &kcrypt_context.key_provider);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize cipher\n");
        if (ret == CPLIB_ERR_ARG) {
            print_lib_usage(KCRYPT_CIPHER_LIB_DIR, options.cipher);
        }
        goto error_cleanup;
    }

    ret = kcrypt_context.key_provider->initialize(kcrypt_context.key_provider, kcrypt_context.key);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize key provider\n");
        goto error_cleanup;
    }


    LOG_DEBUG("Arguments processed successfully\n");
    return CPLIB_ERR_SUCCESS;

    error_cleanup:
    if (*(&kcrypt_context.cipher_factory)) {
        cplib_destroyable_put(kcrypt_context.cipher_factory);
        kcrypt_context.cipher_factory = NULL;
    }
    if (*(&kcrypt_context.key_provider)) {
        cplib_destroyable_put(kcrypt_context.key_provider);
        kcrypt_context.key_provider = NULL;
    }
    if (*(&kcrypt_context.padder)) {
        cplib_destroyable_put(kcrypt_context.padder);
        kcrypt_context.padder = NULL;
    }
    if (*(&kcrypt_context.mode)) {
        cplib_destroyable_put(kcrypt_context.mode);
        kcrypt_context.mode = NULL;
    }
    if (*(&kcrypt_context.writer)) {
        cplib_destroyable_put(kcrypt_context.writer);
        kcrypt_context.writer = NULL;
    }
    if (*(&kcrypt_context.block_iterator)) {
        cplib_destroyable_put(kcrypt_context.block_iterator);
        kcrypt_context.block_iterator = NULL;
    }
    if (*(&kcrypt_context.key)) {
        cplib_destroyable_put(kcrypt_context.key);
        kcrypt_context.key = NULL;
    }
    CPLIB_PUT_IF_EXISTS(message);

    return ret;
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
        print_usage();
        return CPLIB_ERR_ARG;
    }

    if (strncmp(argv[1], "help", 4) == 0) {

        if (strncmp(argv[2], "cipher", 6) == 0) {
            if (argc == 3) {
                print_available_libs(KCRYPT_CIPHER_LIB_DIR);
            } else {
                print_lib_usage(KCRYPT_CIPHER_LIB_DIR, argv[3]);
            }

            return CPLIB_ERR_HELP;
        } else if (strncmp(argv[2], "mode", 4) == 0) {

            if (argc == 3) {
                print_available_libs(KCRYPT_MODE_LIB_DIR);
            } else {
                print_lib_usage(KCRYPT_MODE_LIB_DIR, argv[3]);
            }

            return CPLIB_ERR_HELP;
        }

        print_usage();
        return CPLIB_ERR_HELP;
    }

    options.cipher = argv[1];

    // argv + 1: skip the cipher arg.
    while ((opt = getopt(argc - 1, argv + 1, "p:k:l:o:f:m:c:d:")) != -1) {
        switch (opt) {
            case 'd':
                options.mode = optarg;
                break;
            case 'f':
                if (options.message) {
                    LOG_MSG("Provide either -f, -m or neither\n");
                    print_usage();
                    return CPLIB_ERR_ARG;
                }

                options.input_path = optarg;
                break;
            case 'k':
                if (options.key_path) {
                    LOG_MSG("Provide either -k or -l\n");
                    print_usage();
                    return CPLIB_ERR_ARG;
                }
                options.key = optarg;
                break;
            case 'l':
                if (options.key) {
                    LOG_MSG("Provide either -k or -l\n");
                    print_usage();
                    return CPLIB_ERR_ARG;
                }
                options.key_path = optarg;
                break;
            case 'm':
                if (options.input_path) {
                    LOG_MSG("Provide either -f, -m or neither\n");
                    print_usage();
                    return CPLIB_ERR_ARG;
                }
                options.message = optarg;
                break;
            case 'o':
                options.output_path = optarg;
                break;
            case 'p':
                if (options.process != CPLIB_PROC_NONE) {
                    LOG_MSG("Must provide -p only once\n");
                    print_usage();
                    return CPLIB_ERR_ARG;
                }

                if (optarg[0] == 'd') {
                    options.process = CPLIB_PROC_DECRYPT;
                } else if (optarg[0] == 'e') {
                    options.process = CPLIB_PROC_ENCRYPT;
                } else {
                    LOG_MSG("Invalid process type\n");
                    print_usage();
                }
                break;
            default:
                LOG_MSG("Unknown arg: %c\n", opt);
                print_usage();
                return CPLIB_ERR_ARG;
        }

    }

    LOG_DEBUG("Arguments parsed:\n"
              "options->process: %d\n"
              "options->cipher: %s\n"
              "options->input_path: %s\n"
              "options->key_path: %s\n"
              "options->key: %s\n"
              "options->output_path: %s\n"
              "options->message: %s\n"
              "options->mode: %s\n",
              options.process,
              options.cipher,
              options.input_path,
              options.key_path,
              options.key,
              options.output_path,
              options.message,
              options.mode);

    if (optind >= argc) {
        LOG_MSG("Missing option argument\n");
        print_usage();
        return CPLIB_ERR_ARG;
    }

    if (optind == -1) {
        return CPLIB_ERR_SUCCESS;
    }
    // optind is pointing at the next arg. Hence, the actual number of args consumed is one less than optind.
    options.remaining_argc = argc - optind - 1;
    options.remaining_argv = argv + optind + 1;

    set_module_args();
    return CPLIB_ERR_SUCCESS;
}


int main(int argc, char **argv) {
    int ret;
    init_options();
    init_context();
    char *error_text;

    ret = parse_args(argc, argv);
    if (ret != CPLIB_ERR_SUCCESS) {
        if (ret == CPLIB_ERR_HELP) {
            return CPLIB_ERR_SUCCESS;
        }

        LOG_MSG("Failed to parse arguments. code: %d\n", ret);
        goto cleanup;
    }

    ret = process_parsed_args();

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to process arguments. code: %d\n", ret);
        goto cleanup;
    }


    ret = run_kcrypt();
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("KCrypt failed. Code: %d\n", ret);
        goto cleanup;
    }

    cleanup:

    if (kcrypt_context.mode_module_api.get_error_text != NULL) {
        error_text = kcrypt_context.mode_module_api.get_error_text(
                (struct kcrypt_shared_module_api_t *) &kcrypt_context.mode_module_api);
        if (error_text[0] != 0) {
            LOG_MSG("Mode: %s\n", error_text);
        }
    }


    if (kcrypt_context.cipher_module_api.get_error_text != NULL) {
        error_text = kcrypt_context.cipher_module_api.get_error_text(
                (struct kcrypt_shared_module_api_t *) &kcrypt_context.cipher_module_api);
        if (error_text[0] != 0) {
            LOG_MSG("Cipher: %s\n", error_text);
        }
    }

    if (kcrypt_context.mode_module_api.destroy != NULL) {
        kcrypt_context.mode_module_api.destroy(&kcrypt_context.mode_module_api);
    }

    if (kcrypt_context.cipher_module_api.destroy != NULL) {
        kcrypt_context.cipher_module_api.destroy(&kcrypt_context.cipher_module_api);
    }

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

// TODO NULL check failing for some reason. Also, memory leak in parse args message var. allocd block iterator should split lazily
