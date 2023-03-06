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

    cipher_driver->writer = writer;
    cipher_driver->cipher_factory = cipher_factory;
    cipher_driver->key_provider = key_provider;
    cipher_driver->block_padder = block_padder;
    cipher_driver->block_iterator = block_iterator;
    cipher_driver->mode = mode;
    cipher_driver->run(cipher_driver);
    cleanup:

    CPLIB_PUT_IF_EXISTS(cipher_driver);
    CPLIB_PUT_IF_EXISTS(cipher_factory);
    CPLIB_PUT_IF_EXISTS(key_provider);

    return ret;
}

int get_key(char *key_bytes, char *key_path, cplib_mem_chunk_t **key) {
    ssize_t ret;
    int fd;
    struct stat key_stat;

    if (key_bytes) {
        *key = cplib_mem_chunk_new(key_bytes, strlen(key_bytes) + 1);
        if (!*key) {
            LOG_MSG("Failed to allocate memory for key\n");
            return CPLIB_ERR_MEM;
        }

        return CPLIB_ERR_SUCCESS;
    }

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

    ret = read(fd, (*key)->mem, key_stat.st_size);
    if (ret == -1) {
        LOG_MSG("Failed to read %s due to error: %s\n", key_path, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    return CPLIB_ERR_SUCCESS;
}

int get_block_iterator(int input_fd, char *data_bytes, size_t iterated_size,
                       cplib_block_iterator_base_t **block_iterator) {
    if (data_bytes) {
        cplib_mem_chunk_t *data = cplib_mem_chunk_new(data_bytes, strlen(data_bytes));
        if (!data) {
            LOG_MSG("Failed to allocate memory for data\n");
            return CPLIB_ERR_MEM;
        }

        *block_iterator = cplib_allocated_block_iterator_new(data, iterated_size);
        if (!*block_iterator) {
            LOG_MSG("Failed to create block iterator\n");
            return CPLIB_ERR_MEM;
        }

        return CPLIB_ERR_SUCCESS;
    }

    if (input_fd) {
        *block_iterator = cplib_file_block_iterator_new(input_fd, iterated_size, KCRYPT_FILE_BUFFER_SIZE);
        if (!*block_iterator) {
            LOG_MSG("Failed to create block iterator\n");
            return CPLIB_ERR_MEM;
        }

        return CPLIB_ERR_SUCCESS;
    }

    LOG_MSG("Must provide either data_bytes or input_fd\n");
    return CPLIB_ERR_ARG;
}

void print_usage(char *exe_name) {
    fprintf(stderr,
            "Usage: %s [-d | -e] [-k <key> | -l <key file>] [-o <output file>] [-f <input file> | -m <message>]\n"
            "-e encrypt\n"
            "-d decrypt\n"
            "if -o is not provided writes to stdout\n"
            "if -f or -m is not provided reads from stdin ", exe_name);
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
    char *input_path = NULL;
    char *output_path = NULL;
    char *key_path = NULL;
    char *key_data = NULL;
    char *message = NULL;
    int opt;

    /*
     * -e encrypt
     * -d decrypt
     * -k key
     * -l key file
     * -o output file
     * -f input file
     * -m message
     */
    while ((opt = getopt(argc, argv, "edk:l:o:f:m:")) != -1) {
        switch (opt) {
            case 'e':
                if (*process != CPLIB_PROC_NONE) {
                    print_usage(argv[0]);
                    return CPLIB_ERR_ARG;
                }
                *process = CPLIB_PROC_ENCRYPT;
                break;
            case 'd':
                if (*process != CPLIB_PROC_NONE) {
                    print_usage(argv[0]);
                    return CPLIB_ERR_ARG;
                }
                *process = CPLIB_PROC_DECRYPT;
                break;
            case 'k':
                if (key_path) {
                    print_usage(argv[0]);
                    return CPLIB_ERR_ARG;
                }
                key_data = optarg;
                break;
            case 'l':
                if (key_data) {
                    print_usage(argv[0]);
                    return CPLIB_ERR_ARG;
                }
                key_path = optarg;
                break;
            case 'o':
                output_path = optarg;
                break;
            case 'f':
                if (message) {
                    print_usage(argv[0]);
                    return CPLIB_ERR_ARG;
                }
                input_path = optarg;
                break;
            case 'm':
                if (input_path) {
                    print_usage(argv[0]);
                    return CPLIB_ERR_ARG;
                }
                message = optarg;
                break;
            default:
                print_usage(argv[0]);
                return CPLIB_ERR_ARG;

        }
    }

    if (!key_path && !key_data) {
        print_usage(argv[0]);
        ret = CPLIB_ERR_ARG;
        return ret;
    }

    if (!output_path) {
        LOG_DEBUG("Output directed to stdout\n");
        output_fd = STDOUT_FILENO;
    } else {
        output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (output_fd == -1) {
            LOG_MSG("Failed to open output file %s\n", output_path);
            ret = CPLIB_ERR_FILE;
            return ret;
        }
    }


    ret = get_key(key_data, key_path, key);
    if (ret != CPLIB_ERR_SUCCESS) {
        return ret;
    }

    *writer = (cplib_writer_base_t *) cplib_file_writer_new(output_fd);
    if (!*writer) {
        LOG_MSG("Failed to create writer\n");
        ret = CPLIB_ERR_MEM;
        return ret;
    }

    if (input_path) {
        input_fd = open(input_path, O_RDONLY);
        if (input_fd == -1) {
            LOG_MSG("Failed to open input file %s\n", input_path);
            return CPLIB_ERR_FILE;
        }
    } else if (!message) {
        LOG_DEBUG("Reading message from stdin\n");
        input_path = STDIN_FILENO;
    }


    ret = get_block_iterator(input_fd, message, (*key)->taken, block_iterator);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to get block iterator. code: %d\n", ret);
        return ret;
    }

    return CPLIB_ERR_SUCCESS;
}


int main(int argc, char **argv) {
    int ret;

    enum cplib_proc_type process = CPLIB_PROC_NONE;
    cplib_mem_chunk_t *key;
    cplib_block_iterator_base_t *block_iterator = NULL;
    cplib_mode_base_t *mode = NULL;
    cplib_block_padder_base_t *padder = NULL;
    cplib_writer_base_t *writer = NULL;

    ret = parse_args(argc, argv, &block_iterator, &writer, &key, &mode, &padder, &process);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to parse arguments. code: %d\n", ret);
        goto cleanup;
    }


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
    CPLIB_PUT_IF_EXISTS(key);

    return ret;
}
