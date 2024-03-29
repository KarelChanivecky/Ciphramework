/**
 * Karel Chanivecky 2CPLIB_ERR_SUCCESS23.
 */

#include "ciphrameworklib.h"
#include "cplib_log.h"

int cplib_cipher_base_destroy(cplib_cipher_base_t *cipher) {
    LOG_VERBOSE("Destroying cplib_cipher_base_t %p\n", (void *) cipher);
    cipher->process = NULL;
    cipher->destroy = NULL;
    cipher->initialize = NULL;
    cplib_free(cipher);
    return CPLIB_ERR_SUCCESS;
}

int cplib_default_initializer(void *_, ...) {
    (void) _;
    return CPLIB_ERR_SUCCESS;
}


cplib_cipher_base_t *cplib_cipher_base_new(size_t struct_size, cplib_process_f process) {
    cplib_cipher_base_t *cipher = (cplib_cipher_base_t *) cplib_destroyable_new(struct_size);
    if (!cipher) {
        LOG_DEBUG("Cannot allocate _cipher. Out of memory\n");
        return NULL;
    }
    cipher->initialize = (cplib_cipher_base_init_f) cplib_default_initializer;
    cipher->process = process;
    cipher->destroy = (cplib_independent_mutator_f) cplib_cipher_base_destroy;
    return cipher;
}

cplib_cipher_base_t *cplib_cipher_new(cplib_process_f process) {
    return cplib_cipher_base_new(sizeof(cplib_cipher_base_t), process);
}


// ------------------------------------------------------------------------

int cplib_cipher_factory_base_destroy(cplib_cipher_factory_base_t *factory) {
    LOG_VERBOSE("Destroying cplib_cipher_factory_base_t %p\n", (void *) factory);
    CPLIB_PUT_IF_EXISTS(factory->context);
    factory->destroy = NULL;
    cplib_free(factory);
    return CPLIB_ERR_SUCCESS;
}

cplib_cipher_factory_base_t *
cplib_cipher_factory_base_new(size_t struct_size, cplib_cipher_base_allocator_f allocator) {
    cplib_cipher_factory_base_t *cipher_factory = (cplib_cipher_factory_base_t *) cplib_destroyable_new(struct_size);
    if (!cipher_factory) {
        LOG_DEBUG("Cannot allocate cipher_factory. Out of memory\n");
        return NULL;
    }

    cipher_factory->allocate = allocator;
    cipher_factory->destroy = (cplib_independent_mutator_f) cplib_cipher_factory_base_destroy;
    cipher_factory->context = NULL;
    return cipher_factory;
}


cplib_cipher_factory_base_t *cplib_cipher_factory_new(cplib_cipher_base_allocator_f allocator) {
    return cplib_cipher_factory_base_new(sizeof(cplib_cipher_factory_base_t), allocator);
}

// ------------------------------------------------------------------------

int cplib_writer_base_destroy(cplib_writer_base_t *writer) {
    LOG_VERBOSE("Destroying cplib_writer_base_t %p\n", (void *) writer);

    writer->write = NULL;
    writer->destroy = NULL;
    cplib_free(writer);
    return CPLIB_ERR_SUCCESS;
}

cplib_writer_base_t *cplib_writer_base_new(size_t struct_size, cplib_write_data_f write) {
    cplib_writer_base_t *writer = (cplib_writer_base_t *) cplib_destroyable_new(struct_size);
    if (!writer) {
        LOG_DEBUG("Cannot allocate writer. Out of memory\n");
        return NULL;
    }

    writer->write = write;
    writer->destroy = (cplib_independent_mutator_f) cplib_writer_base_destroy;
    return writer;
}

cplib_writer_base_t *cplib_writer_new(cplib_write_data_f write) {
    return cplib_writer_base_new(sizeof(cplib_writer_base_t), write);
}

// ------------------------------------------------------------------------

int cplib_block_manipulator_base_destroy(cplib_block_manipulator_base_t *manipulator) {
    LOG_VERBOSE("Destroying cplib_block_manipulator_base_t %p\n", (void *) manipulator);

    manipulator->split = NULL;
    manipulator->join = NULL;
    manipulator->destroy = NULL;
    cplib_free(manipulator);
    return CPLIB_ERR_SUCCESS;
}

cplib_block_manipulator_base_t *
cplib_block_manipulator_base_new(size_t struct_size, cplib_block_split_f split, cplib_block_join_f join,
                                 cplib_block_xor_f xor) {
    cplib_block_manipulator_base_t *block_manipulator = (cplib_block_manipulator_base_t *) cplib_destroyable_new(
            struct_size);
    if (!block_manipulator) {
        LOG_DEBUG("Cannot allocate block_manipulator. Out of memory\n");
        return NULL;
    }

    block_manipulator->split = split;
    block_manipulator->join = join;
    block_manipulator->destroy = (cplib_independent_mutator_f) cplib_block_manipulator_base_destroy;
    block_manipulator->xor = xor;

    return block_manipulator;
}


cplib_block_manipulator_base_t *
cplib_block_manipulator_new(cplib_block_split_f split, cplib_block_join_f join, cplib_block_xor_f xor) {
    return cplib_block_manipulator_base_new(sizeof(cplib_block_manipulator_base_t), split, join, xor);
}

// ------------------------------------------------------------------------

int cplib_block_iterator_base_destroy(cplib_block_iterator_base_t *block_iterator) {
    LOG_VERBOSE("Destroying cplib_block_iterator_base_t %p\n", (void *) block_iterator);

    block_iterator->next = NULL;
    block_iterator->is_empty = NULL;
    block_iterator->destroy = NULL;
    if (block_iterator->context) {
        cplib_destroyable_put(block_iterator->context);
        block_iterator->context = NULL;
    }

    cplib_free(block_iterator);
    return CPLIB_ERR_SUCCESS;
}

cplib_block_iterator_base_t *
cplib_block_iterator_base_new(size_t struct_size,
                              cplib_next_item_f next,
                              cplib_empty_f is_empty) {
    cplib_block_iterator_base_t *block_iterator;

    block_iterator = (cplib_block_iterator_base_t *) cplib_destroyable_new(struct_size);
    if (!block_iterator) {
        LOG_DEBUG("Cannot allocate block_iterator. Out of memory\n");
        return NULL;
    }

    block_iterator->next = next;
    block_iterator->is_empty = is_empty;
    block_iterator->destroy = (cplib_independent_mutator_f) cplib_block_iterator_base_destroy;
    block_iterator->context = NULL;

    return block_iterator;
}


cplib_block_iterator_base_t *
cplib_block_iterator_new(cplib_next_item_f next, cplib_empty_f is_empty) {
    return cplib_block_iterator_base_new(sizeof(cplib_block_iterator_base_t), next, is_empty);
}

// ------------------------------------------------------------------------


int cplib_block_padder_base_destroy(cplib_block_padder_base_t *padder) {
    LOG_VERBOSE("Destroying cplib_block_padder_base_t %p\n", (void *) padder);

    padder->pad = NULL;
    padder->unpad = NULL;
    padder->destroy = NULL;
    cplib_free(padder);
    return CPLIB_ERR_SUCCESS;
}

cplib_block_padder_base_t *
cplib_block_padder_base_new(size_t struct_size, cplib_block_pad_f pad, cplib_block_unpad_f unpad) {
    cplib_block_padder_base_t *block_padder = (cplib_block_padder_base_t *) cplib_destroyable_new(struct_size);
    if (!block_padder) {
        LOG_DEBUG("Cannot allocate block_padder. Out of memory\n");
        return NULL;
    }

    block_padder->pad = pad;
    block_padder->unpad = unpad;
    block_padder->destroy = (cplib_independent_mutator_f) cplib_block_padder_base_destroy;

    return block_padder;
}

cplib_block_padder_base_t *cplib_block_padder_new(cplib_block_pad_f pad, cplib_block_unpad_f unpad) {
    return cplib_block_padder_base_new(sizeof(cplib_block_padder_base_t), pad, unpad);
}

// ------------------------------------------------------------------------

int cplib_key_provider_base_destroy(cplib_key_provider_base_t *key_provider) {
    LOG_VERBOSE("Destroying cplib_key_provider_base_t %p\n", (void *) key_provider);

    key_provider->next = NULL;
    key_provider->destroy = NULL;
    key_provider->initialize = NULL;
    cplib_free(key_provider);
    return CPLIB_ERR_SUCCESS;
}

cplib_key_provider_base_t *cplib_key_provider_base_new(size_t struct_size, cplib_next_item_f next) {
    cplib_key_provider_base_t *key_provider = (cplib_key_provider_base_t *) cplib_destroyable_new(struct_size);
    if (!key_provider) {
        LOG_DEBUG("Cannot allocate key_provider. Out of memory\n");
        return NULL;
    }

    key_provider->next = next;
    key_provider->destroy = (cplib_independent_mutator_f) cplib_key_provider_base_destroy;
    key_provider->initialize = (cplib_mem_chunk_func) cplib_default_initializer;
    return key_provider;
}


cplib_key_provider_base_t *cplib_key_provider_new(cplib_next_item_f next) {
    return cplib_key_provider_base_new(sizeof(cplib_key_provider_base_t), next);
}

// ------------------------------------------------------------------------

int cplib_round_key_provider_base_destroy(cplib_round_key_provider_base_t *round_key_provider) {
    round_key_provider->round_index = 0;
    round_key_provider->initialize = NULL;
    round_key_provider->destroy = NULL;
    round_key_provider->next = NULL;
    if (round_key_provider->round_keys) {
        for (unsigned int i = 0; i < round_key_provider->round_keys_count; i++) {
            CPLIB_PUT_IF_EXISTS(round_key_provider->round_keys[i]);
        }
        cplib_free(round_key_provider->round_keys);
    }

    round_key_provider->round_keys_count = 0;
    cplib_free(round_key_provider);
    return CPLIB_ERR_SUCCESS;
}

cplib_round_key_provider_base_t *cplib_round_key_provider_base_new(size_t struct_size,
                                                                   cplib_mem_chunk_func initialize,
                                                                   cplib_next_item_f next) {

    cplib_round_key_provider_base_t *key_provider = (cplib_round_key_provider_base_t *) cplib_key_provider_base_new(
            struct_size, next);
    if (!key_provider) {
        LOG_DEBUG("Cannot allocate round_key_provider. Out of memory\n");
        return NULL;
    }

    key_provider->round_index = 0;
    key_provider->round_keys_count = 0;
    key_provider->round_keys = NULL;
    key_provider ->destroy = (cplib_independent_mutator_f) cplib_round_key_provider_base_destroy;
    key_provider->initialize = initialize;

    return key_provider;
}

cplib_round_key_provider_base_t *cplib_round_key_provider_new(cplib_mem_chunk_func initialize, cplib_next_item_f next) {
    return cplib_round_key_provider_base_new(sizeof(cplib_round_key_provider_base_t), initialize, next);
}

cplib_round_key_provider_base_t *cplib_round_key_provider_new2(cplib_mem_chunk_func initialize) {
    return cplib_round_key_provider_base_new(sizeof(cplib_round_key_provider_base_t), initialize,
                                             (cplib_next_item_f) cplib_round_key_provider_next);
}

int cplib_round_key_provider_next(cplib_round_key_provider_base_t *self, cplib_mem_chunk_t **next_key) {
    if (self->round_index >= self->round_keys_count) {
        *next_key = NULL;
        return CPLIB_ERR_ITER_OVERFLOW;
    }


    *next_key = self->round_keys[self->round_index];
    cplib_destroyable_hold(self->round_keys[self->round_index]);

    self->round_index++;

    return CPLIB_ERR_SUCCESS;
}

int cplib_round_key_provider_same(cplib_round_key_provider_base_t *self, cplib_mem_chunk_t **next_key) {
    if (self->round_index == 0) {
        *next_key = NULL;
        return CPLIB_ERR_ITER_OVERFLOW;
    }

    *next_key = self->round_keys[0];
    cplib_destroyable_hold(self->round_keys[0]);

    self->round_index--;

    return CPLIB_ERR_SUCCESS;
}

int cplib_round_key_provider_next_reverse(cplib_round_key_provider_base_t *self, cplib_mem_chunk_t **next_key) {
    if (self->round_index >= self->round_keys_count) {
        *next_key = NULL;
        return CPLIB_ERR_ITER_OVERFLOW;
    }

    *next_key = self->round_keys[self->round_keys_count - self->round_index - 1];
    cplib_destroyable_hold(self->round_keys[self->round_keys_count - self->round_index - 1]);

    self->round_index++;

    return CPLIB_ERR_SUCCESS;
}

// ------------------------------------------------------------------------

cplib_key_provider_base_t *cplib_key_provider_from_chunk(cplib_key_provider_factory_base_t *self,
                                                         cplib_mem_chunk_t *key) {
    int ret;
    cplib_key_provider_base_t *key_provider = self->allocate(self);
    if (!key_provider) {
        return NULL;
    }

    ret = key_provider->initialize(key_provider, key);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to initialize key_provider. Code: %d\n", ret);
        key_provider->destroy(key_provider);
        return NULL;
    }
    return key_provider;
}

int cplib_key_provider_factory_base_destroy(cplib_key_provider_factory_base_t *self) {
    LOG_VERBOSE("Destroying cplib_key_provider_factory_base_t %p\n", (void *) self);

    self->from = NULL;
    self->destroy = NULL;
    CPLIB_PUT_IF_EXISTS(self->context);

    cplib_free(self);
    return CPLIB_ERR_SUCCESS;
}

cplib_key_provider_factory_base_t *
cplib_key_provider_factory_base_new(size_t struct_size, cplib_key_provider_allocator_f allocator) {
    cplib_key_provider_factory_base_t *key_provider_factory =
            (cplib_key_provider_factory_base_t *) cplib_destroyable_new(struct_size);
    if (!key_provider_factory) {
        LOG_DEBUG("Cannot allocate key_provider_factory. Out of memory\n");
        return NULL;
    }

    key_provider_factory->allocate = allocator;
    key_provider_factory->from = cplib_key_provider_from_chunk;
    key_provider_factory->destroy = (cplib_independent_mutator_f) cplib_key_provider_factory_base_destroy;
    return key_provider_factory;
}

cplib_key_provider_factory_base_t *cplib_key_provider_factory_new(cplib_key_provider_allocator_f allocator) {
    return cplib_key_provider_factory_base_new(sizeof(cplib_key_provider_factory_base_t), allocator);
}


// ------------------------------------------------------------------------


int cplib_mode_base_destroy(cplib_mode_base_t *mode) {
    LOG_VERBOSE("Destroying cplib_mode_base_t %p\n", (void *) mode);

    mode->post_cipher_transform = NULL;
    mode->pre_cipher_transform = NULL;
    cplib_free(mode);
    return CPLIB_ERR_SUCCESS;
}

cplib_mode_base_t *cplib_mode_base_new(size_t struct_size,
                                       cplib_mode_pre_transform_f pre_transform,
                                       cplib_mode_post_transform_f post_transform) {
    cplib_mode_base_t *mode = (cplib_mode_base_t *) cplib_destroyable_new(struct_size);
    if (!mode) {
        LOG_DEBUG("Cannot allocate mode. Out of memory\n");
        return NULL;
    }
    mode->pre_cipher_transform = pre_transform;
    mode->post_cipher_transform = post_transform;
    mode->destroy = (cplib_independent_mutator_f) cplib_mode_base_destroy;
    return mode;
}

cplib_mode_base_t *
cplib_mode_new(cplib_mode_pre_transform_f pre_transform, cplib_mode_post_transform_f post_transform) {
    return cplib_mode_base_new(sizeof(cplib_mode_base_t), pre_transform, post_transform);
}

// ------------------------------------------------------------------------

int cplib_cipher_provider_base_destroy(cplib_cipher_provider_base_t *provider) {
    LOG_VERBOSE("Destroying cplib_cipher_provider_base_t %p\n", (void *) provider);

    provider->destroy = NULL;
    provider->next = NULL;
    cplib_free(provider);
    return CPLIB_ERR_SUCCESS;
}

cplib_cipher_provider_base_t *cplib_cipher_provider_base_new(size_t struct_size, cplib_next_item_f next) {
    cplib_cipher_provider_base_t *cipher_provider =
            (cplib_cipher_provider_base_t *) cplib_destroyable_new(struct_size);
    if (!cipher_provider) {
        LOG_DEBUG("Cannot allocate cipher_provider. Out of memory\n");
        return NULL;
    }

    cipher_provider->next = next;

    return cipher_provider;
}

cplib_cipher_provider_base_t *cplib_cipher_provider_new(cplib_next_item_f next) {
    return cplib_cipher_provider_base_new(sizeof(cplib_cipher_provider_base_t), next);
}

// ------------------------------------------------------------------------
