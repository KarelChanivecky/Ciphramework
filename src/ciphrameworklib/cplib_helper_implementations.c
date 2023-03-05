/**
 * Karel Chanivecky 2023.
 */

#include "cplib_helper_implementations.h"
#include "log.h"


int cplib_keyed_key_provider_default_next(void *g_self, void **key) {
    cplib_keyed_key_provider_t *self = (cplib_keyed_key_provider_t *) g_self;
    *key = self->key;
    return CPLIB_ERR_SUCCESS;
}

int cplib_keyed_key_provider_destroy(cplib_keyed_key_provider_t *self) {
    if (self->key) {
        self->key->destroy(self->key);
        self->key = NULL;
    }

    return cplib_key_provider_base_destroy((cplib_key_provider_base_t *) self);
}

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new(size_t struct_size, cplib_next_item_f next) {
    cplib_keyed_key_provider_t *keyed_key_provider =
            (cplib_keyed_key_provider_t *) cplib_key_provider_base_new(struct_size, next);
    if (!keyed_key_provider) {
        LOG_DEBUG("Cannot allocate keyed_key_provider. Out of memory\n");
        return NULL;
    }

    keyed_key_provider->key = NULL; // given in call to initialize
    keyed_key_provider->next = cplib_keyed_key_provider_default_next;
    return keyed_key_provider;
}


cplib_keyed_key_provider_t *cplib_keyed_key_provider_new2(cplib_next_item_f next) {
    return cplib_keyed_key_provider_new(sizeof(cplib_keyed_key_provider_t), next);
}


// ------------------------------------------------------------------------

int round_cipher_process(
        cplib_cipher_base_t *g_self,
        cplib_mem_chunk_t *data,
        cplib_mem_chunk_t *root_key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **processed) {

    int ret;
    cplib_round_cipher_base_t *self = (cplib_round_cipher_base_t *) g_self;
    cplib_key_provider_base_t *key_provider;
    cplib_cipher_provider_base_t *cipher_provider = self->cipher_provider;
    cplib_cipher_base_t *cipher = NULL;
    cplib_mem_chunk_t *key = NULL;
    key_provider = self->key_provider_factory->from(self->key_provider_factory, root_key);

    if (!key_provider) {
        return CPLIB_ERR_MEM;
    }

    ret = cipher_provider->next(cipher_provider, (void **) &cipher);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to get cipher from cipher_provider. ret=%d\n", ret);
        return ret;
    }

    while (cipher) {
        ret = key_provider->next(key_provider, (void **) &key);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to get key from key_provider. ret=%d\n", ret);
            return ret;
        }

        ret = cipher->process(cipher, data, key, position, processed);
        if (ret) {
            return ret;
        }

        data = *processed;

        ret = cipher_provider->next(cipher_provider, (void **) &cipher);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to get cipher from cipher_provider. ret=%d\n", ret);
            return ret;
        }
    }

    return CPLIB_ERR_SUCCESS;
}

int cplib_round_cipher_base_destroy(cplib_round_cipher_base_t *self) {
    if (self->key_provider) {
        self->key_provider->destroy(self->key_provider);
        self->key_provider = NULL;
    }

    if (self->cipher_provider) {
        self->cipher_provider->destroy(self->cipher_provider);
        self->cipher_provider = NULL;
    }

    if (self->key_provider_factory) {
        self->key_provider_factory->destroy(self->key_provider_factory);
        self->key_provider_factory = NULL;
    }

    return cplib_cipher_base_destroy((cplib_cipher_base_t *) self);
}

cplib_round_cipher_base_t *
cplib_round_cipher_base_new(size_t struct_size, cplib_cipher_provider_base_t *cipher_provider,
                            cplib_key_provider_factory_base_t *key_provider_factory) {
    cplib_round_cipher_base_t *round_cipher =
            (cplib_round_cipher_base_t *) cplib_cipher_base_new(struct_size, round_cipher_process);
    if (!round_cipher) {
        LOG_DEBUG("Cannot allocate round_cipher. Out of memory\n");
        return NULL;
    }

    round_cipher->cipher_provider = cipher_provider;
    round_cipher->key_provider_factory = key_provider_factory;
    round_cipher->key_provider = NULL;

    return round_cipher;
}

cplib_round_cipher_base_t *cplib_round_cipher_new(cplib_cipher_provider_base_t *cipher_provider,
                                                  cplib_key_provider_factory_base_t *key_provider_factory) {
    return cplib_round_cipher_base_new(
            sizeof(cplib_round_cipher_base_t), cipher_provider, key_provider_factory);
}

// ------------------------------------------------------------------------


int cplib_feistel_cipher_encrypt(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *plaintext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **ciphertext_ptr) {

    int ret;
    cplib_mem_chunk_t *plaintext_halves[2] = {0}; // allocated by split
    cplib_mem_chunk_t *ciphertext_halves[2] = {0};
    cplib_mem_chunk_t *round_function_result;
    ciphertext_halves[0] = cplib_allocate_mem_chunk_new(plaintext->size / 2);
    ciphertext_halves[1] = cplib_allocate_mem_chunk_new(plaintext->size / 2);
    round_function_result = cplib_allocate_mem_chunk_new(plaintext->size / 2);

    if (!ciphertext_halves[0] || !ciphertext_halves[1] || !round_function_result) {
        LOG_DEBUG("Failed to allocate memory for encryption. Out of memory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    ret = self->block_manipulator->split(self->block_manipulator, plaintext, plaintext->size / 2, plaintext_halves);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to split plaintext. ret=%d\n", ret);
        goto cleanup;
    }

    ciphertext_halves[0] = plaintext_halves[1];

    ret = self->round_function(self->round_function_self, plaintext_halves[1], &round_function_result, key, position);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Round function failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->xor(self->block_manipulator, round_function_result, plaintext_halves[0], &ciphertext_halves[1]);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("XOR failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->join(self->block_manipulator, ciphertext_halves, 2, ciphertext_ptr);

    cleanup:

    for (int i = 0; i < 2; i++) {
        if (plaintext_halves[i]) {
            plaintext_halves[i]->destroy(plaintext_halves[i]);
        }

        if (ciphertext_halves[i]) {
            ciphertext_halves[i]->destroy(ciphertext_halves[i]);
        }

        if (round_function_result) {
            round_function_result->destroy(round_function_result);
        }
    }

    return ret;
}

int cplib_feistel_cipher_decrypt(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *ciphertext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **plaintext_ptr) {

    int ret;
    cplib_mem_chunk_t *ciphertext_halves[2] = {0}; // allocated by split
    cplib_mem_chunk_t *plaintext_halves[2] = {0};
    cplib_mem_chunk_t *round_function_result;
    plaintext_halves[0] = cplib_allocate_mem_chunk_new(ciphertext->size / 2);
    plaintext_halves[1] = cplib_allocate_mem_chunk_new(ciphertext->size / 2);
    round_function_result = cplib_allocate_mem_chunk_new(ciphertext->size / 2);

    if (!ciphertext_halves[0] || !ciphertext_halves[1] || !round_function_result) {
        LOG_DEBUG("Failed to allocate memory for encryption. Out of memory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    plaintext_halves[0]->taken = plaintext_halves[0]->size;
    plaintext_halves[1]->taken = plaintext_halves[1]->size;
    round_function_result->taken = round_function_result->size;


    ret = self->block_manipulator->split(self->block_manipulator, ciphertext, ciphertext->size / 2, ciphertext_halves);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to split ciphertext. ret=%d\n", ret);
        goto cleanup;
    }

    plaintext_halves[1] = ciphertext_halves[0];

    ret = self->round_function(self->round_function_self, plaintext_halves[1], &round_function_result, key, position);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Round function failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->xor(self->block_manipulator, round_function_result, ciphertext_halves[1], &plaintext_halves[0]);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("XOR failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->join(self->block_manipulator, plaintext_halves, 2, plaintext_ptr);

    LOG_DEBUG("Feistel round finished.\n");

    cleanup:

    for (int i = 0; i < 2; i++) {
        if (plaintext_halves[i]) {
            plaintext_halves[i]->destroy(plaintext_halves[i]);
        }

        if (ciphertext_halves[i]) {
            ciphertext_halves[i]->destroy(ciphertext_halves[i]);
        }

        if (round_function_result) {
            round_function_result->destroy(round_function_result);
        }
    }

    return ret;
}


int cplib_feistel_cipher_destroy(cplib_feistel_cipher_t *self) {
    self->round_function = NULL;
    if (self->round_function_self) {
        self->round_function_self->destroy(self->round_function_self);
    }
    return cplib_cipher_base_destroy((cplib_cipher_base_t *) self);
}

cplib_feistel_cipher_t *
cplib_feistel_cipher_new(cplib_process_f decrypt_or_encrypt_func,
                         cplib_feistel_round_f round_function,
                         cplib_destroyable_t *round_function_self,
                         cplib_block_manipulator_base_t *block_manipulator) {
    cplib_feistel_cipher_t *cipher = (cplib_feistel_cipher_t *) cplib_cipher_base_new(
            sizeof(cplib_feistel_cipher_t), decrypt_or_encrypt_func);
    if (!cipher) {
        return NULL;
    }

    cipher->round_function = round_function;
    cipher->block_manipulator = block_manipulator;
    cipher->round_function_self = round_function_self;
    cipher->destroy = (cplib_independent_mutator_f) cplib_feistel_cipher_destroy;
    return cipher;
}

