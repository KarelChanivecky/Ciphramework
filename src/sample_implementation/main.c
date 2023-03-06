#include <stdio.h>

#include "kcrypt.h"
#include "cplib_utils.h"
#include "cplib_log.h"
#include "xor_cipher.h"



int process(
        cplib_mem_chunk_t *key,
        cplib_block_iterator_base_t *block_iterator,
        cplib_mem_chunk_t *input_file_path,
        cplib_mem_chunk_t *output_file_path,
        enum cplib_proc_type process
) {
    int ret;
    cplib_cipher_driver_t *cipher_driver = NULL;
    cplib_writer_base_t *writer = NULL;
    cplib_cipher_factory_base_t *cipher_factory = NULL;
    cplib_key_provider_base_t *key_provider = NULL;
    cplib_block_padder_base_t *block_padder = NULL;

    writer = (cplib_writer_base_t *) cplib_file_writer_new(output_file_path);
    if (!writer) {
        LOG_MSG("Failed to create writer\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

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

    block_padder = cplib_pkcs5_padder_new(process);
    if (!block_padder) {
        LOG_MSG("Failed to create block padder\n");
        ret = CPLIB_ERR_MEM;
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

    cipher_driver->run(cipher_driver);
    cleanup:

    CPLIB_PUT_IF_EXISTS(cipher_driver);
    CPLIB_PUT_IF_EXISTS(writer);
    CPLIB_PUT_IF_EXISTS(cipher_factory);
    CPLIB_PUT_IF_EXISTS(key_provider);
    CPLIB_PUT_IF_EXISTS(block_padder);
    CPLIB_PUT_IF_EXISTS(key);
    CPLIB_PUT_IF_EXISTS(data);
    CPLIB_PUT_IF_EXISTS(output_file_path);
    return ret;
}

int main(int argc, char **argv) {


    int process;
cplib_block_iterator_base_t *block_iterator = NULL;

    if (data) {
        block_iterator = cplib_allocated_block_iterator_new();
        if (!block_iterator) {
            LOG_DEBUG("Failed to allocate block iterator\n");
            return CPLIB_ERR_MEM;
        }

        ret = block_iterator->initialize(block_iterator, data, key->taken);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to initialize block iterator\n");
            return ret;
        }

    } else if (input_file_path) {
        block_iterator = cplib_file_block_iterator_new(input_file_path, key->taken, KCRYPT_FILE_BUFFER_SIZE);
        if (!block_iterator) {
            LOG_DEBUG("Failed to allocate file block iterator\n");
            return CPLIB_ERR_MEM;
        }
    } else {
        LOG_DEBUG("Must provide either data or input file path\n");
        return CPLIB_ERR_ARG;
    }


    return 0;
}
