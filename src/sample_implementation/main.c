#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"
#include "xor_cipher.h"


int run_kcrypt(
        cplib_mem_chunk_t *key,
        cplib_block_iterator_base_t *block_iterator,
        cplib_writer_base_t *writer,
        enum cplib_proc_type process,
        cplib_mode_base_t *mode,
        cplib_block_padder_base_t *block_padder
) {
    int ret;
    cplib_cipher_driver_t *cipher_driver = NULL;
    cplib_cipher_factory_base_t *cipher_factory = NULL;
    cplib_key_provider_base_t *key_provider = NULL;


    key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        LOG_MSG("Failed to create key provider\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    ret = key_provider->initialize(key_provider, key);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to initialize key provider\n");
        goto cleanup;
    }

    cipher_factory = get_xor_cipher_factory(process);
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
    cipher_driver->run(cipher_driver);

    cleanup:

    CPLIB_PUT_IF_EXISTS(cipher_driver);
    CPLIB_PUT_IF_EXISTS(key_provider);
    CPLIB_PUT_IF_EXISTS(cipher_factory);

    return ret;
}


int get_key(cplib_mem_chunk_t *key_path, cplib_mem_chunk_t **key) {
    ssize_t ret;
    int fd;
    struct stat key_stat;
    LOG_DEBUG("Getting key from file %s\n", (char *) key_path->mem);

    fd = open(key_path->mem, O_RDONLY);
    if (fd == -1) {
        LOG_MSG("Failed to open %s due to error: %s\n", (char *) key_path->mem, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    ret = fstat(fd, &key_stat);
    if (ret == -1) {
        LOG_MSG("Failed to stat %s due to error: %s\n", (char *) key_path->mem, strerror(errno));
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
        LOG_MSG("Failed to read %s due to error: %s\n", (char *) key_path->mem, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    if (ret != key_stat.st_size) {
        LOG_MSG("Failed to read key from file.\n");
    }

    (*key)->taken = key_stat.st_size;

    return CPLIB_ERR_SUCCESS;
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

    if (input_fd != CPLIB_CLOSED_FD) {
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
            "Usage: %s <-p d | -p e> [-k <key> | -l <key file>] [-o <output file>] [-f <input file> | -m <message>]\n"
            "-p e encrypt\n"
            "-p d decrypt\n"
            "if -o is not provided writes to stdout\n"
            "if -f or -m is not provided reads message from stdin\n", exe_name);
}

int parse_args(
        int argc,
        char **argv,
        cplib_block_iterator_base_t **block_iterator,
        cplib_writer_base_t **writer,
        cplib_mem_chunk_t **key,
        cplib_mode_base_t **mode,
        cplib_block_padder_base_t **padder,
        enum cplib_proc_type *process) {

    int ret;
    int input_fd = CPLIB_CLOSED_FD;
    int output_fd = CPLIB_CLOSED_FD;
    cplib_mem_chunk_t *input_path = NULL;
    cplib_mem_chunk_t *output_path = NULL;
    cplib_mem_chunk_t *key_path = NULL;
    cplib_mem_chunk_t *message = NULL;
    int opt;
    LOG_DEBUG("Parsing arguments\n");
    /*
     * -p e encrypt
     * -p d decrypt
     * -k key
     * -l key file
     * -o output file
     * -f input file
     * -m message
     */
    while ((opt = getopt(argc, argv, "p:k:l:o:f:m:")) != -1) {
        switch (opt) {

            case 'd':
                if (*process != CPLIB_PROC_NONE) {
                    LOG_MSG("-p option can only be used once\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                *process = CPLIB_PROC_DECRYPT;
                break;
            case 'e':
                if (*process != CPLIB_PROC_NONE) {
                    LOG_MSG("-p option can only be used once\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                *process = CPLIB_PROC_ENCRYPT;
                break;
            case 'f':
                if (message) {
                    LOG_MSG("Provide either -f, -m or neither\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }

                input_path = cplib_mem_chunk_str_new(optarg);
                if (!input_path) {
                    LOG_MSG("Failed to allocate memory for input path\n");
                    ret = CPLIB_ERR_MEM;
                    goto error_cleanup;
                }
                break;
            case 'k':
                if (key_path) {
                    LOG_MSG("Provide either -k or -l\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                *key = cplib_mem_chunk_str_new(optarg);
                if (!*key) {
                    LOG_MSG("Failed to allocate memory for key\n");
                    ret = CPLIB_ERR_MEM;
                    goto error_cleanup;
                }
                (*key)->taken--; // ignore null byte
                break;
            case 'l':
                if (*key) {
                    LOG_MSG("Provide either -k or -l\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                key_path = cplib_mem_chunk_str_new(optarg);
                if (!key_path) {
                    LOG_MSG("Failed to allocate memory for key path\n");
                    ret = CPLIB_ERR_MEM;
                    goto error_cleanup;
                }
                break;
            case 'o':
                output_path = cplib_mem_chunk_str_new(optarg);
                if (!output_path) {
                    LOG_MSG("Failed to allocate memory for output path\n");
                    ret = CPLIB_ERR_MEM;
                    goto error_cleanup;
                }
                break;
            case 'm':
                if (input_path) {
                    LOG_MSG("Provide either -f, -m or neither\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                message = cplib_mem_chunk_str_new(optarg);
                if (!message) {
                    LOG_MSG("Failed to allocate memory for message\n");
                    ret = CPLIB_ERR_MEM;
                    goto error_cleanup;
                }
                message->taken--; // ignore null byte
                break;
            case 'p':
                if (optarg[0] == 'd') {
                    *process = CPLIB_PROC_DECRYPT;
                } else if (optarg[0] == 'e') {
                    *process = CPLIB_PROC_ENCRYPT;
                } else {
                    LOG_MSG("Invalid process type\n");
                    print_usage(argv[0]);
                    ret = CPLIB_ERR_ARG;
                    goto error_cleanup;
                }
                break;
            default:
                LOG_MSG("Unknown arg: %c\n", opt);
                print_usage(argv[0]);
                ret = CPLIB_ERR_ARG;
                goto error_cleanup;
        }
    }

    LOG_DEBUG("Arguments analyzed. Initializing parameters\n");

    if (*process == CPLIB_PROC_NONE) {
        LOG_MSG("No process specified\n");
        print_usage(argv[0]);
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    if (!key_path && !*key) {
        print_usage(argv[0]);
        ret = CPLIB_ERR_ARG;
        goto error_cleanup;
    }

    if (!output_path) {
        LOG_DEBUG("Output directed to stdout\n");
        output_fd = STDOUT_FILENO;
    } else {
        output_fd = open(output_path->mem, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd == -1) {
            LOG_MSG("Failed to open output file %s\n", (char *) output_path->mem);
            ret = CPLIB_ERR_FILE;
            goto error_cleanup;
        }
    }

    if (key_path) {
        ret = get_key(key_path, key);
        if (ret != CPLIB_ERR_SUCCESS) {
            goto error_cleanup;
        }
    }


    *writer = (cplib_writer_base_t *) cplib_file_writer_new(output_fd);
    if (!*writer) {
        LOG_MSG("Failed to create writer\n");
        ret = CPLIB_ERR_MEM;
        goto error_cleanup;
    }

    if (input_path) {
        input_fd = open(input_path->mem, O_RDONLY);
        if (input_fd == -1) {
            LOG_MSG("Failed to open input file %s\n", (char *) input_path->mem);
            ret = CPLIB_ERR_FILE;
            goto error_cleanup;
        }
    } else if (!message) {
        LOG_DEBUG("Reading message from stdin\n");
        input_fd = STDIN_FILENO;
    }


    ret = get_block_iterator(input_fd, message, (*key)->taken, block_iterator);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get block iterator. code: %d\n", ret);
        goto error_cleanup;
    }

    *padder = cplib_pkcs5_padder_new(*process);
    if (!*padder) {
        LOG_MSG("Failed to allocate padder\n");
        ret = CPLIB_ERR_MEM;
        goto error_cleanup;
    }

    LOG_DEBUG("Arguments parsed successfully\n");
    ret = CPLIB_ERR_SUCCESS;
    goto cleanup;

    error_cleanup:
    CPLIB_PUT_IF_EXISTS(*key);
    CPLIB_PUT_IF_EXISTS(*block_iterator);
    CPLIB_PUT_IF_EXISTS(*writer);
    CPLIB_PUT_IF_EXISTS(*mode);
    CPLIB_PUT_IF_EXISTS(*padder);
    *process = CPLIB_PROC_NONE;

    cleanup:
    CPLIB_PUT_IF_EXISTS(input_path);
    CPLIB_PUT_IF_EXISTS(output_path);
    CPLIB_PUT_IF_EXISTS(key_path);
    CPLIB_PUT_IF_EXISTS(message);
    return ret;
}


int main(int argc, char **argv) {
    int ret;

    enum cplib_proc_type process = CPLIB_PROC_NONE;
    cplib_mem_chunk_t *key = NULL;
    cplib_block_iterator_base_t *block_iterator = NULL;
    cplib_mode_base_t *mode = NULL;
    cplib_block_padder_base_t *padder = NULL;
    cplib_writer_base_t *writer = NULL;

    ret = parse_args(argc, argv, &block_iterator, &writer, &key, &mode, &padder, &process);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to parse arguments. code: %d\n", ret);
        return ret;
    }

    CPLIB_HOLD_IF_EXISTS(block_iterator);
    CPLIB_HOLD_IF_EXISTS(mode);
    CPLIB_HOLD_IF_EXISTS(padder);
    CPLIB_HOLD_IF_EXISTS(writer);

    ret = run_kcrypt(key, block_iterator, writer, process, mode, padder);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("KCrypt failed. Code: %d\n", ret);
        goto cleanup;
    }

    cleanup:

    CPLIB_PUT_IF_EXISTS(key);
    CPLIB_PUT_IF_EXISTS(block_iterator);
    CPLIB_PUT_IF_EXISTS(mode);
    CPLIB_PUT_IF_EXISTS(padder);
    CPLIB_PUT_IF_EXISTS(writer);

    if (ret == CPLIB_ERR_SUCCESS) {
        return EXIT_SUCCESS;
    }

    return ret;
}
