/**
 * Karel Chanivecky 2023.
 */

#include <string.h>

#include "ciphrameworklib.h"
#include "cplib_log.h"


int set_to_process_message(cplib_cipher_driver_t *driver,
                           cplib_cipher_base_t **cipher,
                           cplib_mem_chunk_t **key,
                           int *empty) {
    int ret;
    cplib_cipher_base_t *c;

    c = driver->cipher_factory->allocate(driver->cipher_factory);
    if (!cipher) {
        LOG_MSG("Failed to allocate cipher.\n");
        return CPLIB_ERR_MEM;
    }

    c->initialize(c, driver->_cipher);
    CPLIB_PUT_IF_EXISTS(driver->_cipher);
    driver->_cipher = c;
    *cipher = c;


    ret = driver->block_iterator->is_empty(driver->block_iterator, empty);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("ERROR: Failed to get block. ret=%d\n", ret);
        return ret;
    }

    ret = driver->key_provider->next(driver->key_provider, (void **) key);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("ERROR: Failed to get key. ret=%d\n", ret);
        return ret;
    }

    return CPLIB_ERR_SUCCESS;
}

int evaluate_padding(cplib_cipher_driver_t *driver,
                     int empty,
                     cplib_mem_chunk_t *block,
                     cplib_mem_chunk_t **extra,
                     cplib_mem_chunk_t **padded) {
    int ret;

    cplib_mem_chunk_t *p;
    cplib_mem_chunk_t *e;

    e = *extra;
    p = *padded;

    if (driver->block_padder && driver->block_padder->pad && empty && !e) {

        ret = driver->block_padder->pad(driver->block_padder, block, driver->block_size, &p, &e);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to pad block. ret=%d\n", ret);
            return ret;
        }
        LOG_VERBOSE("Padded\n");

        *extra = e;

    } else {
        CPLIB_PUT_IF_EXISTS(*extra); // here we consume extra so we do not loop back. We also had to free it

        if (!p) {
            p = cplib_allocate_mem_chunk(block->size);
        }

        if (!p) {
            LOG_MSG("ERROR: Out of memory\n");
            return CPLIB_ERR_MEM;
        }
        p->recycle(p, block->mem, block->taken);
    }

    *padded = p;
    return CPLIB_ERR_SUCCESS;
}

int evaluate_pre_cipher_mode(cplib_cipher_driver_t *driver,
                             cplib_mem_chunk_t *key,
                             cplib_mem_chunk_t *padded,
                             cplib_mem_chunk_t **pre_modded) {
    int ret;
    cplib_mem_chunk_t *pm;

    pm = *pre_modded;
    if (!driver->mode) {
        if (!pm) {
            pm = cplib_allocate_mem_chunk(padded->size);
        }

        if (!pm) {
            LOG_MSG("ERROR: Out of memory\n");
            return CPLIB_ERR_MEM;
        }

        pm->recycle(pm, padded->mem, padded->taken);
    } else {
        ret = driver->mode->pre_cipher_transform(driver->mode, padded, key, driver->block_position, &pm);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to apply pre-cipher mode transform. ret=%d\n", ret);
            return ret;
        }
        LOG_VERBOSE("Pre-modded\n");
    }

    *pre_modded = pm;

    return CPLIB_ERR_SUCCESS;
}

int evaluate_post_cipher_mode(cplib_cipher_driver_t *driver,
                              cplib_mem_chunk_t *key,
                              cplib_mem_chunk_t *block,
                              cplib_mem_chunk_t *processed,
                              cplib_mem_chunk_t **post_modded) {
    int ret;
    cplib_mem_chunk_t *pm;

    pm = *post_modded;

    if (!driver->mode) {
        if (!pm) {
            pm = cplib_allocate_mem_chunk(processed->size);
        }

        if (!pm) {
            LOG_MSG("ERROR: Out of memory\n");
            return CPLIB_ERR_MEM;
        }

        pm->recycle(pm, processed->mem, processed->taken);

    } else {
        ret = driver->mode->post_cipher_transform(driver->mode, processed, block, key, driver->block_position, &pm);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to apply post-cipher mode transform. ret=%d\n", ret);
            return ret;
        }
        LOG_VERBOSE("Post-modded\n");
    }

    *post_modded = pm;
    return CPLIB_ERR_SUCCESS;
}

int evaluate_unpadding(cplib_cipher_driver_t *driver,
                       int empty,
                       cplib_mem_chunk_t * post_modded,
                       cplib_mem_chunk_t ** unpadded) {
    int ret;
    cplib_mem_chunk_t * u;

    u = *unpadded;

    if (driver->block_padder && driver->block_padder->unpad && empty) {
        ret = driver->block_padder->unpad(driver->block_padder, post_modded, &u);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to unpad block. ret=%d\n", ret);
            return ret;
        }
        LOG_VERBOSE("Unpadded\n");
    } else {
        if (!u) {
            u = cplib_allocate_mem_chunk(post_modded->size);
        }

        if (!u) {
            LOG_MSG("ERROR: Out of memory\n");
            return CPLIB_ERR_MEM;
        }

        u->recycle(u, post_modded->mem, post_modded->taken);
    }

    *unpadded = u;

    return CPLIB_ERR_SUCCESS;
}

int cipher_driver_run(cplib_cipher_driver_t *self) {
    int empty = 0;
    int ret;
    size_t cur_block_size;
    cplib_mem_chunk_t *key = NULL;
    cplib_block_iterator_base_t *block_iterator = NULL;
    cplib_writer_base_t *writer = NULL;
    cplib_cipher_base_t *cipher = NULL;
    cplib_mem_chunk_t *extra = NULL;
    cplib_mem_chunk_t *block = NULL;
    cplib_mem_chunk_t *padded = NULL;
    cplib_mem_chunk_t *pre_modded = NULL;
    cplib_mem_chunk_t *processed = NULL;
    cplib_mem_chunk_t *post_modded = NULL;
    cplib_mem_chunk_t *unpadded = NULL;

    // shush compiler warning in release build
    (void) cur_block_size;

    block_iterator = self->block_iterator;

    LOG_VERBOSE("Checking if empty\n");

    ret = block_iterator->is_empty(block_iterator, &empty);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("ERROR: There seems to be no message to process\n");
        return ret;
    }

    LOG_DEBUG("Cipher driver running.\n");
    writer = self->writer;


    while (!empty) {

        ret = block_iterator->next(block_iterator, (void **) &block);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_MSG("ERROR: Failed to get block. ret=%d\n", ret);
            goto cleanup;
        }
        cur_block_size = block->taken;
        LOG_VERBOSE("Got block\n");

        do {
            ret = set_to_process_message(self, &cipher, &key, &empty);
            if (ret != CPLIB_ERR_SUCCESS) {
                goto cleanup;
            }

            if (extra) {
                LOG_VERBOSE("Got extra\n");

                // extra won't be anything but NULL until the last block and if data % key length == 0
                // swap extra into block. We are done, so it shouldn't matter if the chunk were to be smaller
                block->recycle(block, extra->mem, extra->taken);
            }


            LOG_VERBOSE("Set to process message\n");

            ret = evaluate_padding(self, empty, block, &extra, &padded);
            if (ret != CPLIB_ERR_SUCCESS) {
                goto cleanup;
            }

            LOG_VERBOSE("Processed padding\n");

            ret = evaluate_pre_cipher_mode(self, key, padded, &pre_modded);
            if (ret != CPLIB_ERR_SUCCESS) {
                goto cleanup;
            }

            LOG_VERBOSE("Processed mode pre-cipher\n");

            ret = cipher->process((cplib_destroyable_t *) cipher, pre_modded, key, self->block_position, &processed);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Cipher process failed. ret=%d\n", ret);
                goto cleanup;
            }

            LOG_VERBOSE("Processed cipher\n");

            ret = evaluate_post_cipher_mode(self, key, block, processed, &post_modded);
            if (ret != CPLIB_ERR_SUCCESS) {
                goto cleanup;
            }

            LOG_VERBOSE("Processed mode post-cipher\n");

            ret = evaluate_unpadding(self, empty, post_modded, &unpadded);
            if (ret != CPLIB_ERR_SUCCESS) {
                goto cleanup;
            }

            LOG_VERBOSE("Processed unpadding\n");

            ret = writer->write(writer, unpadded);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_MSG("ERROR: Failed to write. ret=%d\n", ret);
                goto cleanup;
            }

            LOG_DEBUG("Cipher driver wrote a chunk of size: %zu.\n", unpadded->taken);

            CPLIB_PUT_IF_EXISTS(key);
            block->taken = 0;
            padded->taken = 0;
            pre_modded->taken = 0;
            processed->taken = 0;
            post_modded->taken = 0;
            unpadded->taken = 0;
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
