/**
 * Karel Chanivecky 2023.
 */

#include <string.h>

#include "ciphrameworklib.h"
#include "log.h"


int cipher_driver_run(cplib_cipher_driver_t *self, cplib_mem_chunk_t *data) {
    int empty = 0;
    int ret;
    cplib_mem_chunk_t *block = NULL;
    cplib_mem_chunk_t *padded = NULL;
    cplib_mem_chunk_t *pre_modded = NULL;
    cplib_mem_chunk_t *extra = NULL;
    cplib_mem_chunk_t *processed = NULL;
    cplib_mem_chunk_t *post_modded = NULL;
    cplib_mem_chunk_t *key = NULL;
    cplib_mem_chunk_t *unpadded = NULL;
    cplib_cipher_base_t *cipher = NULL;
    cplib_key_provider_base_t *key_provider = self->key_provider;
    cplib_block_padder_base_t *block_padder = self->block_padder;
    cplib_block_iterator_base_t *block_iterator;
    cplib_mode_base_t *mode = self->mode;

    LOG_DEBUG("Cipher driver running.\n");

    block_iterator = self->block_iterator_factory->from_chunk(self->block_iterator_factory, data);
    self->block_iterator = block_iterator;

    while (!empty) {
        ret = block_iterator->next(block_iterator, (void **) &block);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to get block. ret=%d\n", ret);
            goto cleanup;
        }

        do {
            if (extra) {
                LOG_DEBUG("Cipher driver got an extra padding chunk.\n");

                // extra won't be anything but NULL until the last block and if data % key length == 0
                // swap extra into block. We are done, so it shouldn't matter if the chunk were to be smaller
                block->destroy(block);
                block = extra;
                extra = NULL;
            }


            empty = block_iterator->is_empty(block_iterator);

            if (block_padder && empty) {
                ret = block_padder->pad(block_padder, block, &padded, &extra);
                if (ret != CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to pad block. ret=%d\n", ret);
                    goto cleanup;
                }
            } else {
                padded = block;
            }

            ret = key_provider->next(key_provider, (void **) &key);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Failed to get key. ret=%d\n", ret);
                goto cleanup;
            }

            if (!mode) {
                pre_modded = padded;
            } else {
                ret = mode->pre_cipher_transform(mode, padded, key, self->block_position, &processed);
                if (ret!= CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to apply pre-cipher mode transform. ret=%d\n", ret);
                    goto cleanup;
                }
            }

            ret = cipher->process(cipher, pre_modded, key, self->block_position, &processed);
            if (ret!= CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Cipher process failed. ret=%d\n", ret);
                goto cleanup;
            }

            if (!mode) {
                post_modded = processed;
            } else {
                ret = mode->post_cipher_transform(mode, processed, unpadded, key, self->block_position, &post_modded);
                if (ret!= CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to apply post-cipher mode transform. ret=%d\n", ret);
                    goto cleanup;
                }
            }

            if (block_padder && empty) {
                ret = block_padder->unpad(block_padder, block, &unpadded);
                if (ret!= CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to unpad block. ret=%d\n", ret);
                    goto cleanup;
                }
            } else {
                unpadded = block;
            }


            LOG_DEBUG("Cipher driver finished another chunk of size: %zu.\n", block->taken);
        } while (extra); // if we have an extra block we need to process that before moving on

    }

    LOG_DEBUG("Cipher driver done. Cleaning up.\n");

    cleanup:

    CPLIB_DESTROY_CHUNK_IF_IS_NOT(pre_modded, padded);
    CPLIB_DESTROY_CHUNK_IF_IS_NOT(padded, block);
    CPLIB_DESTROY_CHUNK_IF_IS_NOT(extra, block);
    CPLIB_DESTROY_CHUNK_IF_IS_NOT(block, NULL);
    CPLIB_DESTROY_CHUNK_IF_IS_NOT(unpadded, post_modded);
    CPLIB_DESTROY_CHUNK_IF_IS_NOT(post_modded, processed);
    CPLIB_DESTROY_CHUNK_IF_IS_NOT(processed, NULL);

    return ret;
}


cplib_cipher_driver_t *cplib_cipher_driver_new(void) {
    cplib_cipher_driver_t *cipher_driver_t = (cplib_cipher_driver_t *) malloc(sizeof(cplib_cipher_driver_t));
    if (!cipher_driver_t) {
        LOG_DEBUG("Cannot allocate cipher_driver_t. Out of memory\n");
        return NULL;
    }

    memset(cipher_driver_t, 0, sizeof(cplib_cipher_driver_t));
    cipher_driver_t->block_position = CPLIB_BLOCK_POS_START;

    return cipher_driver_t;
}


int cplib_cipher_driver_base_destroy(cplib_cipher_driver_t *cipher_driver) {
    cipher_driver->writer->destroy(cipher_driver->writer);
    cipher_driver->key_provider->destroy(cipher_driver->key_provider);
    cipher_driver->cipher_factory->destroy(cipher_driver->cipher_factory);
    cipher_driver->_cipher->destroy(cipher_driver->_cipher);
    cipher_driver->block_iterator->destroy(cipher_driver->block_iterator);
    cipher_driver->block_iterator_factory->destroy(cipher_driver->block_iterator_factory);
    cipher_driver->mode->destroy(cipher_driver->mode);
    cipher_driver->block_padder->destroy(cipher_driver->block_padder);

    cipher_driver->writer = NULL;
    cipher_driver->key_provider = NULL;
    cipher_driver->cipher_factory = NULL;
    cipher_driver->_cipher = NULL;
    cipher_driver->block_padder = NULL;
    cipher_driver->block_iterator = NULL;
    cipher_driver->block_iterator_factory = NULL;
    cipher_driver->mode = NULL;
    cipher_driver->run = cipher_driver_run;

    free(cipher_driver);
    return 0;
}
