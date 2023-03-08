/**
 * Karel Chanivecky 2023.
 */

#include <string.h>

#include "ciphrameworklib.h"
#include "cplib_log.h"


int cipher_driver_run(cplib_cipher_driver_t *self) {
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
    cplib_cipher_base_t *cipher;
    cplib_block_iterator_base_t *block_iterator;
    cplib_key_provider_base_t *key_provider;
    cplib_block_padder_base_t *block_padder;
    cplib_mode_base_t *mode;
    cplib_writer_base_t *writer;
    size_t cur_block_size;
    size_t expected_block_size;

    expected_block_size = self->block_size;
    block_iterator = self->block_iterator;
    key_provider = self->key_provider;
    block_padder = self->block_padder;
    mode = self->mode;

    LOG_VERBOSE("Checking if empty\n");

    ret = block_iterator->is_empty(block_iterator, &empty);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("ERROR: There seems to be no message to process\n");
        return ret;
    }

    LOG_DEBUG("Cipher driver running.\n");
    writer = self->writer;
    cipher = self->cipher_factory->allocate(self->cipher_factory);
    if (cipher == NULL) {
        LOG_MSG("Failed to allocate cipher.\n");
        return -1;
    }

    cipher->initialize(cipher, self->_cipher);
    self->_cipher = cipher;


    while (!empty) {

        ret = block_iterator->next(block_iterator, (void **) &block);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to get block. ret=%d\n", ret);
            goto cleanup;
        }
        cur_block_size = block->taken;
        LOG_VERBOSE("Got block\n");

        do {
            if (extra) {
                LOG_VERBOSE("Got extra\n");

                // extra won't be anything but NULL until the last block and if data % key length == 0
                // swap extra into block. We are done, so it shouldn't matter if the chunk were to be smaller
                block = extra;
            }


            ret = block_iterator->is_empty(block_iterator, &empty);
            if (ret!= CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Failed to get block. ret=%d\n", ret);
                goto cleanup;
            }

            ret = key_provider->next(key_provider, (void **) &key);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Failed to get key. ret=%d\n", ret);
                goto cleanup;
            }

            LOG_VERBOSE("Got key\n");

            if (block_padder && block_padder->pad && empty && !extra) {

                ret = block_padder->pad(block_padder, block, expected_block_size, &padded, &extra);
                if (ret != CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to pad block. ret=%d\n", ret);
                    goto cleanup;
                }
                LOG_VERBOSE("Padded\n");

            } else {
                if (extra) {
                    extra = NULL;
                }
                padded = block;
                cplib_destroyable_hold(block);
            }


            if (!mode) {
                cplib_destroyable_hold(padded);
                pre_modded = padded;
            } else {
                ret = mode->pre_cipher_transform(mode, padded, key, self->block_position, &processed);
                if (ret != CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to apply pre-cipher mode transform. ret=%d\n", ret);
                    goto cleanup;
                }
                LOG_VERBOSE("Pre-modded\n");
            }

            CPLIB_PUT_IF_EXISTS(padded);

            ret = cipher->process((cplib_destroyable_t *) cipher, pre_modded, key, self->block_position, &processed);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Cipher process failed. ret=%d\n", ret);
                goto cleanup;
            }

            LOG_VERBOSE("Processed\n");

            if (!mode) {
                post_modded = processed;
                cplib_destroyable_hold(processed);
            } else {
                ret = mode->post_cipher_transform(mode, processed, block, key, self->block_position, &post_modded);
                if (ret != CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to apply post-cipher mode transform. ret=%d\n", ret);
                    goto cleanup;
                }
                LOG_VERBOSE("Post-modded\n");
            }



            CPLIB_PUT_IF_EXISTS(pre_modded);
            CPLIB_PUT_IF_EXISTS(key);

            if (block_padder && block_padder->unpad && empty) {
                ret = block_padder->unpad(block_padder, post_modded, &unpadded);
                if (ret != CPLIB_ERR_SUCCESS) {
                    LOG_MSG("ERROR: Failed to unpad block. ret=%d\n", ret);
                    goto cleanup;
                }
                LOG_VERBOSE("Unpadded\n");
            } else {
                unpadded = post_modded;
                cplib_destroyable_hold(post_modded);
            }

            CPLIB_PUT_IF_EXISTS(block);
            CPLIB_PUT_IF_EXISTS(post_modded);

            ret = writer->write(writer, unpadded);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Failed to write. ret=%d\n", ret);
                goto cleanup;
            }
            LOG_VERBOSE("Wrote\n");

            LOG_DEBUG("Cipher driver finished a chunk of size: %zu.\n", cur_block_size);

            CPLIB_PUT_IF_EXISTS(unpadded);
        } while (extra); // if we have an extra block we need to process that before moving on

    }

    LOG_DEBUG("Cipher driver done. Cleaning up.\n");

    cleanup:

    CPLIB_PUT_IF_EXISTS(block);
    CPLIB_PUT_IF_EXISTS(extra);
    CPLIB_PUT_IF_EXISTS(padded);
    CPLIB_PUT_IF_EXISTS(pre_modded);
    CPLIB_PUT_IF_EXISTS(processed);
    CPLIB_PUT_IF_EXISTS(post_modded);
    CPLIB_PUT_IF_EXISTS(unpadded);
    CPLIB_PUT_IF_EXISTS(key);
    writer->close(writer);

    return ret;
}


int cplib_cipher_driver_base_destroy(cplib_cipher_driver_t *cipher_driver) {
    LOG_VERBOSE("Destroying cplib_cipher_driver_t %p\n", (void *) cipher_driver);

    CPLIB_PUT_IF_EXISTS(cipher_driver->writer);
    CPLIB_PUT_IF_EXISTS(cipher_driver->key_provider);
    CPLIB_PUT_IF_EXISTS(cipher_driver->cipher_factory);
    CPLIB_PUT_IF_EXISTS(cipher_driver->_cipher);
    CPLIB_PUT_IF_EXISTS(cipher_driver->block_iterator);
    CPLIB_PUT_IF_EXISTS(cipher_driver->mode);
    CPLIB_PUT_IF_EXISTS(cipher_driver->block_padder);

    cplib_free(cipher_driver);
    return CPLIB_ERR_SUCCESS;
}


cplib_cipher_driver_t *cplib_cipher_driver_new(void) {
    cplib_cipher_driver_t *cipher_driver = (cplib_cipher_driver_t *) cplib_destroyable_new(
            sizeof(cplib_cipher_driver_t));
    if (!cipher_driver) {
        LOG_DEBUG("Cannot allocate cipher_driver. Out of memory\n");
        return NULL;
    }

    cipher_driver->block_position = CPLIB_BLOCK_POS_START;
    cipher_driver->destroy = (cplib_independent_mutator_f) cplib_cipher_driver_base_destroy;
    cipher_driver->run = (cplib_independent_mutator_f) cipher_driver_run;
    cipher_driver->block_size = 0;
    return cipher_driver;
}
