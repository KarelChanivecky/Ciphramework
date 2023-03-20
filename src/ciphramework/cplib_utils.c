/**
 * Karel Chanivecky 2023.
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cplib_utils.h"
#include "cplib_log.h"


int cplib_keyed_key_provider_default_next(void *g_self, void **key) {
    cplib_keyed_key_provider_t *self = (cplib_keyed_key_provider_t *) g_self;
    *key = self->key;
    // add a hold because we did not allocate the memory
    cplib_destroyable_hold(*key);
    return CPLIB_ERR_SUCCESS;
}

int cplib_keyed_key_provider_destroy(cplib_keyed_key_provider_t *self) {
    LOG_VERBOSE("Destroying cplib_keyed_key_provider_t %p\n", (void *) self);

    CPLIB_PUT_IF_EXISTS(self->key);
    self->key = NULL;

    return cplib_key_provider_base_destroy((cplib_key_provider_base_t *) self);
}

int keyed_key_provider_default_initialize(cplib_keyed_key_provider_t *self, cplib_mem_chunk_t *key) {
    self->key = key;
    cplib_destroyable_hold(key);
    return CPLIB_ERR_SUCCESS;
}

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new(size_t struct_size, cplib_next_item_f next) {
    cplib_keyed_key_provider_t *keyed_key_provider =
            (cplib_keyed_key_provider_t *) cplib_key_provider_base_new(struct_size, next);
    if (!keyed_key_provider) {
        LOG_DEBUG("Cannot allocate keyed_key_provider. Out of memory\n");
        return NULL;
    }

    keyed_key_provider->key = NULL; // given in call to initialize
    keyed_key_provider->next = next;
    keyed_key_provider->initialize = (cplib_mem_chunk_func) keyed_key_provider_default_initialize;
    keyed_key_provider->destroy = (cplib_independent_mutator_f) cplib_keyed_key_provider_destroy;
    return keyed_key_provider;
}


cplib_keyed_key_provider_t *cplib_keyed_key_provider_new2(cplib_next_item_f next) {
    return cplib_keyed_key_provider_new(sizeof(cplib_keyed_key_provider_t), next);
}

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new3(void) {
    return cplib_keyed_key_provider_new(sizeof(cplib_keyed_key_provider_t), cplib_keyed_key_provider_default_next);
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
    cplib_cipher_base_t * next = NULL;

    if (!key_provider) {
        return CPLIB_ERR_MEM;
    }

    ret = cipher_provider->next(cipher_provider, (void **) &cipher);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to get cipher from cipher_provider. ret=%d\n", ret);
        return ret;
    }

    ret = cipher_provider->next(cipher_provider, (void **) &next);
    if (ret != CPLIB_ERR_SUCCESS && ret != CPLIB_ERR_ITER_OVERFLOW) {
        LOG_DEBUG("Failed to get cipher from cipher_provider. ret=%d\n", ret);
        return ret;
    }

    position = CPLIB_BLOCK_POS_START;

    while (cipher) {
        LOG_DEBUG("Running cipher round\n");

        if (!next) {
            position = CPLIB_BLOCK_POS_END;
        }

        ret = key_provider->next(key_provider, (void **) &key);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to get key from key_provider. ret=%d\n", ret);
            goto cleanup;
        }

        ret = cipher->process((cplib_destroyable_t *)cipher, data, key, position, processed);
        if (ret != CPLIB_ERR_SUCCESS) {
            goto cleanup;
        }
        data = *processed;

        cplib_destroyable_put(key);
        key = NULL;
        cplib_destroyable_put(cipher);
        cipher = NULL;

        position = CPLIB_BLOCK_POS_CENTER;
        cipher = next;
        ret = cipher_provider->next(cipher_provider, (void **) &next);
        if (ret != CPLIB_ERR_SUCCESS) {
            LOG_DEBUG("Failed to get cipher from cipher_provider. ret=%d\n", ret);
            goto cleanup;
        }
    }

    ret = CPLIB_ERR_SUCCESS;

    cleanup:
    CPLIB_PUT_IF_EXISTS(key_provider);
    CPLIB_PUT_IF_EXISTS(cipher);
    CPLIB_PUT_IF_EXISTS(key);
    return ret;
}

int cplib_round_cipher_base_destroy(cplib_round_cipher_base_t *self) {
    LOG_VERBOSE("Destroying cplib_round_cipher_base_t %p\n", (void *) self);

    CPLIB_PUT_IF_EXISTS(self->key_provider);
    CPLIB_PUT_IF_EXISTS(self->cipher_provider);
    CPLIB_PUT_IF_EXISTS(self->key_provider_factory);

    return cplib_cipher_base_destroy((cplib_cipher_base_t *) self);
}

cplib_round_cipher_base_t *
cplib_round_cipher_base_new(size_t struct_size,
                            cplib_cipher_provider_base_t *cipher_provider,
                            cplib_key_provider_factory_base_t *key_provider_factory) {
    cplib_round_cipher_base_t *round_cipher =
            (cplib_round_cipher_base_t *) cplib_cipher_base_new(struct_size, (cplib_process_f) round_cipher_process);
    if (!round_cipher) {
        LOG_DEBUG("Cannot allocate round_cipher. Out of memory\n");
        return NULL;
    }

    round_cipher->cipher_provider = cipher_provider;
    round_cipher->key_provider_factory = key_provider_factory;
    round_cipher->key_provider = NULL;
    round_cipher->destroy = (cplib_independent_mutator_f) cplib_round_cipher_base_destroy;

    return round_cipher;
}

cplib_round_cipher_base_t *cplib_round_cipher_new(cplib_cipher_provider_base_t *cipher_provider,
                                                  cplib_key_provider_factory_base_t *key_provider_factory) {
    return cplib_round_cipher_base_new(
            sizeof(cplib_round_cipher_base_t), cipher_provider, key_provider_factory);
}


cplib_round_cipher_base_t *cplib_round_cipher_new2(cplib_cipher_base_t *cipher,
                                                   int provide_count,
                                                   cplib_key_provider_factory_base_t *key_provider_factory) {
    cplib_cipher_provider_base_t *cipher_provider;

    cipher_provider = (cplib_cipher_provider_base_t *) cplib_same_cipher_provider_new(cipher, provide_count);
    if (!cipher_provider) {
        LOG_DEBUG("Cannot allocate cipher_provider. Out of memory\n");
        return NULL;
    }

    return cplib_round_cipher_base_new(
            sizeof(cplib_round_cipher_base_t), cipher_provider, key_provider_factory);
}
// ------------------------------------------------------------------------


int cplib_feistel_cipher_round(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *plaintext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **ciphertext_ptr) {

    int ret;
    cplib_mem_chunk_t **plaintext_halves = NULL; // chunks themselves are allocated by split
    cplib_mem_chunk_t *ciphertext_halves[2] = {0};
    cplib_mem_chunk_t *round_function_result;
    cplib_mem_chunk_t * swap_temp = NULL;

    plaintext_halves = cplib_malloc(sizeof(cplib_mem_chunk_t *) * 2);
    if (!plaintext_halves) {
        LOG_DEBUG("Cannot allocate plaintext_halves. Out of memory\n");
        return CPLIB_ERR_MEM;
    }

    plaintext_halves[0] = NULL;
    plaintext_halves[1] = NULL;
    ciphertext_halves[0] = cplib_allocate_mem_chunk(plaintext->taken / 2);
    ciphertext_halves[1] = cplib_allocate_mem_chunk(plaintext->taken / 2);
    round_function_result = cplib_allocate_mem_chunk(plaintext->taken / 2);
    unsigned int unused = 2;

    if (!ciphertext_halves[0] || !ciphertext_halves[1] || !round_function_result) {
        LOG_DEBUG("Failed to allocate memory for encryption. Out of memory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    ret = self->block_manipulator->split(self->block_manipulator, plaintext, plaintext->taken / 2,
                                         (cplib_mem_chunk_t ***) &plaintext_halves,
                                         &unused);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to split plaintext. ret=%d\n", ret);
        goto cleanup;
    }

    ciphertext_halves[0]->recycle(ciphertext_halves[0], plaintext_halves[1]->mem, plaintext_halves[1]->taken);

    ret = self->round_function(self->round_function_self, plaintext_halves[1], key, position, &round_function_result);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Round function failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->xor(self->block_manipulator, round_function_result, plaintext_halves[0],
                                       &ciphertext_halves[1]);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("XOR failed. ret=%d\n", ret);
        goto cleanup;
    }

    if (position == CPLIB_BLOCK_POS_END) {
        swap_temp = ciphertext_halves[0];
        ciphertext_halves[0] = ciphertext_halves[1];
        ciphertext_halves[1] = swap_temp;
    }

    ret = self->block_manipulator->join(self->block_manipulator, ciphertext_halves, 2, ciphertext_ptr);

    cleanup:

    for (int i = 0; i < 2; i++) {
        CPLIB_PUT_IF_EXISTS(plaintext_halves[i]);
        CPLIB_PUT_IF_EXISTS(ciphertext_halves[i]);
    }
    CPLIB_PUT_IF_EXISTS(round_function_result);
    cplib_free(plaintext_halves);
    plaintext_halves = NULL;
    return ret;
}

int cplib_feistel_cipher_decrypt(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *ciphertext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **plaintext_ptr) {

    int ret;
    unsigned int unused_var = 2;
    cplib_mem_chunk_t **ciphertext_halves = NULL; // allocated by split
    cplib_mem_chunk_t *plaintext_halves[2] = {0};
    cplib_mem_chunk_t *round_function_result;


    ciphertext_halves = cplib_malloc(sizeof(cplib_mem_chunk_t *) * 2);
    if (!ciphertext_halves) {
        LOG_DEBUG("Cannot allocate plaintext_halves. Out of memory\n");
        return CPLIB_ERR_MEM;
    }

    ciphertext_halves[0] = NULL;
    ciphertext_halves[1] = NULL;
    plaintext_halves[0] = cplib_allocate_mem_chunk(ciphertext->taken / 2);
    plaintext_halves[1] = cplib_allocate_mem_chunk(ciphertext->taken / 2);
    round_function_result = cplib_allocate_mem_chunk(ciphertext->taken / 2);

    if (!plaintext_halves[0] || !plaintext_halves[1] || !round_function_result) {
        LOG_DEBUG("Failed to allocate memory for decryption. Out of memory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    plaintext_halves[0]->taken = plaintext_halves[0]->size;
    plaintext_halves[1]->taken = plaintext_halves[1]->size;
    round_function_result->taken = round_function_result->size;


    ret = self->block_manipulator->split(self->block_manipulator, ciphertext, ciphertext->taken / 2,
                                         (cplib_mem_chunk_t ***) &ciphertext_halves, &unused_var);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to split ciphertext. ret=%d\n", ret);
        goto cleanup;
    }

    plaintext_halves[1]->recycle(plaintext_halves[1], ciphertext_halves[0]->mem, ciphertext_halves[0]->taken);

    ret = self->round_function(self->round_function_self, plaintext_halves[1], key, position, &round_function_result);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Round function failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->xor(self->block_manipulator, round_function_result, ciphertext_halves[1],
                                       &plaintext_halves[0]);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("XOR failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->join(self->block_manipulator, plaintext_halves, 2, plaintext_ptr);

    LOG_DEBUG("Feistel round finished.\n");

    cleanup:

    for (int i = 0; i < 2; i++) {
        CPLIB_PUT_IF_EXISTS(plaintext_halves[i]);
        CPLIB_PUT_IF_EXISTS(ciphertext_halves[i]);
    }

    CPLIB_PUT_IF_EXISTS(round_function_result);
    cplib_free(ciphertext_halves);
    ciphertext_halves = NULL;
    return ret;
}


int cplib_feistel_cipher_destroy(cplib_feistel_cipher_t *self) {
    self->round_function = NULL;
    CPLIB_PUT_IF_EXISTS(self->round_function_self);
    cplib_destroyable_put(self->block_manipulator);

    return cplib_cipher_base_destroy((cplib_cipher_base_t *) self);
}

cplib_feistel_cipher_t *
cplib_feistel_cipher_new(cplib_process_f round_function,
                         cplib_destroyable_t *round_function_self,
                         cplib_block_manipulator_base_t *block_manipulator) {

    cplib_feistel_cipher_t *cipher = (cplib_feistel_cipher_t *) cplib_cipher_base_new(
            sizeof(cplib_feistel_cipher_t), (cplib_process_f) cplib_feistel_cipher_round);
    if (!cipher) {
        return NULL;
    }

    cipher->round_function = round_function;
    cipher->block_manipulator = block_manipulator;
    cipher->round_function_self = round_function_self;
    CPLIB_HOLD_IF_EXISTS(round_function_self);
    cplib_destroyable_hold(block_manipulator);
    cipher->destroy = (cplib_independent_mutator_f) cplib_feistel_cipher_destroy;
    return cipher;
}

struct feistel_cipher_factory_context_t {
    cplib_destroyable_t;
    enum cplib_proc_type process;
    cplib_process_f round_function;
    cplib_destroyable_t * round_function_self;
};

typedef struct feistel_cipher_factory_context_t feistel_cipher_factory_context_t;

int destroy_feistel_cipher_factory_context(feistel_cipher_factory_context_t * self) {
    LOG_VERBOSE("Destroying feistel_cipher_factory_context_t %p\n", (void *) self);

    CPLIB_PUT_IF_EXISTS(self->round_function_self);
    self->process = CPLIB_PROC_NONE;
    self->round_function = NULL;

    return cplib_destroyable_destroy((struct cplib_destroyable_t *) self);
}

cplib_feistel_cipher_t *allocate_feistel_cipher(cplib_cipher_factory_base_t *self) {

    feistel_cipher_factory_context_t *ctx;
    cplib_block_manipulator_base_t * block_manipulator;

    ctx = (feistel_cipher_factory_context_t *) self->context;

    block_manipulator = cplib_simple_block_manipulator_new();

    cplib_feistel_cipher_t *cipher = (cplib_feistel_cipher_t *) cplib_feistel_cipher_new(
            ctx->round_function,
            ctx->round_function_self,
            block_manipulator);

    cplib_destroyable_put(block_manipulator); // destroy or give up ownership

    if (!cipher) {
        return NULL;
    }

    return cipher;
}

cplib_cipher_factory_base_t *
cplib_feistel_cipher_factory_new(cplib_process_f round_function, cplib_destroyable_t * round_function_self) {

    cplib_cipher_factory_base_t *feistel_cipher_factory = cplib_cipher_factory_new(
            (cplib_cipher_base_allocator_f) allocate_feistel_cipher);
    if (!feistel_cipher_factory) {
        return NULL;
    }

    feistel_cipher_factory_context_t *context = (feistel_cipher_factory_context_t *) cplib_destroyable_new(
            sizeof(feistel_cipher_factory_context_t));
    if (!context) {
        LOG_MSG("Failed to allocate memory for feistel cipher factory context.\n");
        cplib_destroyable_put(feistel_cipher_factory);
        return NULL;
    }

    context->round_function = round_function;
    context->round_function_self = round_function_self;
    CPLIB_HOLD_IF_EXISTS(round_function_self);
    context->destroy = (cplib_independent_mutator_f) destroy_feistel_cipher_factory_context;
    feistel_cipher_factory->context = (cplib_destroyable_t *) context;

    return feistel_cipher_factory;
}

// ------------------------------------------------------------------------

int provide_next_cipher(cplib_same_cipher_provider_t *self, cplib_cipher_base_t **cipher) {
    if (!self->provide_count) {
        *cipher = NULL;
        return CPLIB_ERR_SUCCESS;
    }

    self->provide_count--;

    *cipher = self->cipher;
    cplib_destroyable_hold(self->cipher);
    return CPLIB_ERR_SUCCESS;
}

int cplib_same_cipher_provider_destroy(cplib_same_cipher_provider_t *self) {
    LOG_VERBOSE("Destroying cplib_same_cipher_provider_t %p\n", (void *) self);

    cplib_destroyable_put(self->cipher);
    self->cipher = NULL;
    self->provide_count = 0;
    return cplib_cipher_provider_base_destroy((cplib_cipher_provider_base_t *) self);
}

cplib_same_cipher_provider_t *cplib_same_cipher_provider_new(cplib_cipher_base_t *cipher, int provide_count) {
    cplib_same_cipher_provider_t *cipher_provider = (cplib_same_cipher_provider_t *)
            cplib_cipher_provider_base_new(sizeof(cplib_same_cipher_provider_t),
                                           (cplib_next_item_f) provide_next_cipher);
    if (!cipher_provider) {
        return NULL;
    }

    cipher_provider->cipher = cipher;
    cipher_provider->provide_count = provide_count;
    cipher_provider->destroy = (cplib_independent_mutator_f) cplib_same_cipher_provider_destroy;
    return cipher_provider;
}

// ------------------------------------------------------------------------

int cplib_block_split(cplib_block_manipulator_base_t *self,
                      cplib_mem_chunk_t *block,
                      size_t split_size,
                      cplib_mem_chunk_t ***chunks_ptr,
                      unsigned int *chunk_count_ptr) {
    CPLIB_UNUSED_PARAM(self);
    unsigned int chunk_count;
    unsigned int chunk_index;
    size_t chunk_mem_index;
    uint8_t *from_block_data;
    uint8_t *to_block_data;
    cplib_mem_chunk_t **chunks;
    cplib_mem_chunk_t *chunk;

    from_block_data = block->mem;
    chunk_count = block->taken / split_size + ((block->taken % split_size) != 0);
    if (!*chunks_ptr) {
        *chunks_ptr = cplib_malloc(sizeof(cplib_mem_chunk_t *) * chunk_count);
        *chunk_count_ptr = chunk_count;
    }

    chunks = *chunks_ptr;

    if (*chunk_count_ptr < chunk_count) {
        LOG_DEBUG(
                "Was passed a set of chunk already allocated, but there is a count mismatch from what is needed. Got %u != needed %u\n",
                *chunk_count_ptr, chunk_count);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    for (unsigned int i = 0; i < chunk_count; i++) {
        if (!chunks[i]) {
            chunks[i] = cplib_allocate_mem_chunk(split_size);
        }

        if (chunks[i]->size != split_size) {
            LOG_DEBUG("Passed allocated chunk has a size mismatch from what is needed\n");
            return CPLIB_ERR_SIZE_MISMATCH;
        }
    }

    for (unsigned int i = 0; i < block->taken; i++) {
        chunk_index = (int) i / split_size;
        chunk = chunks[chunk_index];
        to_block_data = chunk->mem;
        chunk_mem_index = i % split_size;
        to_block_data[chunk_mem_index] = from_block_data[i];
        chunk->taken++;
    }

    return CPLIB_ERR_SUCCESS;
}

int cplib_block_join(cplib_block_manipulator_base_t *self,
                     cplib_mem_chunk_t **chunks,
                     unsigned int chunk_count,
                     cplib_mem_chunk_t **block_ptr) {
    CPLIB_UNUSED_PARAM(self);
    size_t total_size = 0;
    cplib_mem_chunk_t *temp_chunk;
    cplib_mem_chunk_t *block;
    size_t joint_index = 0;
    uint8_t *from_block_data;
    uint8_t *to_block_data;

    for (unsigned int i = 0; i < chunk_count; i++) {
        total_size += chunks[i]->taken;
    }

    if (!*block_ptr) {
        *block_ptr = cplib_allocate_mem_chunk(total_size);
        if (!*block_ptr) {
            LOG_DEBUG("Failed to allocate memory for joint block\n");
        }
    }

    block = *block_ptr;

    if (block->size != total_size) {
        LOG_DEBUG("Passed allocated block has a size mismatch from what is needed: got %zu != needed %zu\n",
                  block->size,
                  total_size);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    to_block_data = block->mem;
    block->taken = total_size;

    for (unsigned int i = 0; i < chunk_count; i++) {
        temp_chunk = chunks[i];
        from_block_data = temp_chunk->mem;
        for (unsigned int j = 0; j < temp_chunk->taken; j++) {
            to_block_data[joint_index] = from_block_data[j];
            joint_index++;
        }
    }

    return CPLIB_ERR_SUCCESS;
}

int cplib_block_xor(struct cplib_block_manipulator_base_t *self,
                    cplib_mem_chunk_t *one,
                    cplib_mem_chunk_t *other,
                    cplib_mem_chunk_t **result_ptr) {
    CPLIB_UNUSED_PARAM(self);

    cplib_mem_chunk_t *result;
    uint8_t *result_data;
    uint8_t *left_operand_data;
    uint8_t *right_operand_data;

    if (one->taken != other->taken) {
        LOG_DEBUG("Passed block sizes do not match. %zu != %zu\n", one->taken, other->taken);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    if (!*result_ptr) {
        *result_ptr = cplib_allocate_mem_chunk(one->taken);
        if (!*result_ptr) {
            LOG_DEBUG("Failed to allocate memory for xor block\n");
            return CPLIB_ERR_MEM;
        }
    }

    result = *result_ptr;
    if (result->size < one->taken) {
        LOG_DEBUG("Passed result block size is is not large enough. Given: %zu != Need: %zu\n", result->size,
                  one->taken);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    result->taken = one->taken;

    left_operand_data = one->mem;
    right_operand_data = other->mem;
    result_data = result->mem;

    for (unsigned int i = 0; i < one->taken; i++) {
        result_data[i] = left_operand_data[i] ^ right_operand_data[i];
    }

    return CPLIB_ERR_SUCCESS;
}

cplib_block_manipulator_base_t *cplib_simple_block_manipulator_new(void) {
    return cplib_block_manipulator_new(cplib_block_split, cplib_block_join, cplib_block_xor);
}

// ------------------------------------------------------------------------

int pkcs5_block_pad(cplib_block_padder_base_t *self,
                    cplib_mem_chunk_t *data,
                    size_t key_len,
                    cplib_mem_chunk_t **padded_ptr,
                    cplib_mem_chunk_t **extra_ptr) {
    CPLIB_UNUSED_PARAM(self);

    cplib_mem_chunk_t *padded;
    cplib_mem_chunk_t *extra;
    cplib_mem_chunk_t *to_pad;
    size_t pad_len;

    if (key_len > UINT8_MAX) {
        LOG_MSG("This PKCS#5 padding implementation only supports keys up to %ud bytes long.\n ", UINT8_MAX);
    }

    if (!*padded_ptr) {
        *padded_ptr = cplib_allocate_mem_chunk(key_len);
        if (!*padded_ptr) {
            LOG_DEBUG("Failed to allocate memory for padding block\n");
            return CPLIB_ERR_MEM;
        }
    }

    padded = *padded_ptr;

    if (padded->size < key_len) {
        LOG_DEBUG("Passed padded block is smaller than needed: got %zu!= need %zu\n", padded->size, key_len);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    pad_len = key_len - data->taken;

    if (pad_len) {
        LOG_DEBUG("Padding block with pad length of %zu because: %zu < %zu\n", pad_len, data->taken, key_len);
        memcpy(padded->mem, data->mem, data->taken);
        padded->taken = data->taken;
        to_pad = padded;
    } else {
        LOG_DEBUG("Padding extra block because block_size = key_size\n");

        if (!*extra_ptr) {
            *extra_ptr = cplib_allocate_mem_chunk(key_len);
            if (!*extra_ptr) {
                LOG_DEBUG("Failed to allocate memory for extra block\n");
                return CPLIB_ERR_MEM;
            }
        }

        extra = *extra_ptr;

        if (extra->size < key_len) {
            LOG_DEBUG("Passed extra block is smaller than needed: got %zu!= need %zu\n", extra->size, key_len);
            return CPLIB_ERR_SIZE_MISMATCH;
        }
        padded->recycle(padded, data->mem, data->taken);
        to_pad = extra;
        pad_len = key_len;
    }

    memset((uint8_t *) to_pad->mem + to_pad->taken, (uint8_t) pad_len, pad_len);
    to_pad->taken += pad_len;

    return CPLIB_ERR_SUCCESS;
}

int pkcs5_block_unpad(cplib_block_padder_base_t *self, cplib_mem_chunk_t *data, cplib_mem_chunk_t **unpadded_ptr) {
    CPLIB_UNUSED_PARAM(self);

    cplib_mem_chunk_t *unpadded;
    size_t pad_len;
    size_t unpadded_block_len;
    uint8_t *data_mem;

    data_mem = data->mem;
    pad_len = data_mem[data->taken - 1];
    unpadded_block_len = data->taken - pad_len;

    if (!*unpadded_ptr) {
        *unpadded_ptr = cplib_allocate_mem_chunk(unpadded_block_len);
        if (!*unpadded_ptr) {
            LOG_DEBUG("Failed to allocate memory for unpadded block\n");
            return CPLIB_ERR_MEM;
        }
    }

    unpadded = *unpadded_ptr;

    if (unpadded->size < unpadded_block_len) {
        LOG_DEBUG("Passed unpadded block size is not large enough to accommodate unpadded block. %zu!= %zu\n",
                  unpadded->size,
                  unpadded_block_len);
        return CPLIB_ERR_SIZE_MISMATCH;
    }

    memcpy(unpadded->mem, data_mem, unpadded_block_len);

    unpadded->taken = unpadded_block_len;

    LOG_DEBUG("Unpadded block of length: %zu\n", unpadded_block_len);
    return CPLIB_ERR_SUCCESS;
}

cplib_block_padder_base_t *cplib_pkcs5_padder_new(enum cplib_proc_type process_type) {
    if (process_type == CPLIB_PROC_ENCRYPT) {
        return cplib_block_padder_new(pkcs5_block_pad, NULL);
    }

    return cplib_block_padder_new(NULL, pkcs5_block_unpad);
}

// ------------------------------------------------------------------------


int file_writer_flush(cplib_file_writer_t *self) {
    if (fsync(self->fd) == -1) {
        LOG_MSG("Failed to fsync file due to error: %s\n", strerror(errno));
        return CPLIB_ERR_OS;
    }
    return CPLIB_ERR_SUCCESS;
}

int file_writer_write(cplib_file_writer_t *self, cplib_mem_chunk_t *data) {
    ssize_t ret;

    if (self->fd == CPLIB_INVALID_FD) {
        return CPLIB_ERR_FILE;
    }

    ret = write(self->fd, data->mem, data->taken);
    if (ret == -1) {
        LOG_MSG("Failed to write to file due to error: %s\n", strerror(errno));
        return CPLIB_ERR_OS;
    }

    if ((size_t) ret != data->taken) {
        LOG_MSG("Incomplete write to file. written: %zd < to write: %zu\n", ret, data->taken);
        return CPLIB_ERR_OS;
    }

#ifdef CPLIB_DEBUG
    self->flush(self);
#endif

    return CPLIB_ERR_SUCCESS;
}

int file_writer_close(cplib_file_writer_t *self) {
    int ret;
    if (self->fd != CPLIB_INVALID_FD) {
        return CPLIB_ERR_SUCCESS;
    }

    ret = close(self->fd);
    self->fd = CPLIB_INVALID_FD;

    if (ret == -1) {
        LOG_MSG("Failed to close file due to error: %s\n", strerror(errno));
        return CPLIB_ERR_OS;
    }

    return CPLIB_ERR_SUCCESS;
}

int file_writer_destroy(cplib_file_writer_t *self) {
    LOG_VERBOSE("Destroying cplib_file_writer_t %p\n", (void *) self);

    self->close(self);
    return cplib_writer_base_destroy((cplib_writer_base_t *) self);
}


cplib_file_writer_t *cplib_file_writer_new(int fd) {
    cplib_file_writer_t *writer = (cplib_file_writer_t *)
            cplib_writer_base_new(sizeof(cplib_file_writer_t), (cplib_write_data_f) file_writer_write);

    writer->fd = fd;
    writer->destroy = (cplib_independent_mutator_f) file_writer_destroy;
    writer->close = (cplib_independent_mutator_f) file_writer_close;
    writer->flush = (cplib_independent_mutator_f) file_writer_flush;
    return writer;
}

// ------------------------------------------------------------------------

struct allocated_block_iterator_context_t {
    cplib_destroyable_t;
    cplib_mem_chunk_t **chunks;
    unsigned int chunk_count;
    unsigned int next_chunk;
};

typedef struct allocated_block_iterator_context_t allocated_block_iterator_context_t;

int destroy_allocated_block_iterator_context(allocated_block_iterator_context_t *ctx) {
    LOG_VERBOSE("Destroying allocated_block_iterator_context_t %p\n", (void *) ctx);

    cplib_mem_chunk_t *chunk;

    for (unsigned int i = 0; i < ctx->chunk_count; i++) {
        chunk = ctx->chunks[i];
        cplib_destroyable_put(chunk);
    }
    cplib_free(ctx->chunks);
    cplib_free(ctx);
    return CPLIB_ERR_SUCCESS;
}


int block_allocated_iterator_next(cplib_block_iterator_base_t *self, cplib_mem_chunk_t **next_ptr) {
    allocated_block_iterator_context_t *ctx;
    cplib_mem_chunk_t *next;
    int ret;
    int empty;

    ctx = (allocated_block_iterator_context_t *) self->context;

    ret = self->is_empty(self, &empty);
    if (ret != CPLIB_ERR_SUCCESS) {
        return ret;
    }

    if (empty) {
        return CPLIB_ERR_ITER_OVERFLOW;
    }

    next = ctx->chunks[ctx->next_chunk];
    *next_ptr = next;
    cplib_destroyable_hold(next);

    ctx->next_chunk++;
    return CPLIB_ERR_SUCCESS;
}

int block_allocated_iterator_is_empty(cplib_block_iterator_base_t *self, int *result) {
    allocated_block_iterator_context_t *ctx = (allocated_block_iterator_context_t *) self->context;
    *result = ctx->next_chunk >= ctx->chunk_count;
    return CPLIB_ERR_SUCCESS;
}


cplib_block_iterator_base_t *cplib_allocated_block_iterator_new(cplib_mem_chunk_t *data, size_t iterated_size) {
    int ret;
    cplib_block_iterator_base_t *block_iterator;
    allocated_block_iterator_context_t *ctx;

    ctx = (allocated_block_iterator_context_t *) cplib_destroyable_new(
            sizeof(struct allocated_block_iterator_context_t));
    if (!ctx) {
        LOG_DEBUG("Failed to allocate block iterator context\n");
        return NULL;
    }

    ctx->destroy = (cplib_independent_mutator_f) destroy_allocated_block_iterator_context;
    ret = cplib_block_split(NULL, data, iterated_size, &ctx->chunks, &ctx->chunk_count);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to split block\n");
    }

    ctx->next_chunk = 0;


    block_iterator = cplib_block_iterator_new(
            (cplib_next_item_f) block_allocated_iterator_next,
            (cplib_empty_f) block_allocated_iterator_is_empty);

    if (!block_iterator) {
        LOG_DEBUG("Failed to allocate block iterator\n");
        cplib_destroyable_put(ctx);
        return NULL;
    }
    block_iterator->context = (cplib_destroyable_t *) ctx;

    return block_iterator;
}

// ------------------------------------------------------------------------

struct file_block_iterator_context_t {
    cplib_destroyable_t;
    cplib_mem_chunk_t *buffer;
    int fd;
    int got_eof;
    size_t iterated_size;
    cplib_block_iterator_base_t *allocated_iterator;
};

typedef struct file_block_iterator_context_t file_block_iterator_context_t;


int destroy_file_block_iterator_context(file_block_iterator_context_t *ctx) {
    LOG_VERBOSE("Destroying file_block_iterator_context_t %p\n", (void *) ctx);

    if (ctx->fd != CPLIB_INVALID_FD) {
        close(ctx->fd);
        ctx->fd = CPLIB_INVALID_FD;
    }
    ctx->got_eof = 0;
    CPLIB_PUT_IF_EXISTS(ctx->allocated_iterator);
    CPLIB_PUT_IF_EXISTS(ctx->buffer);

    return cplib_destroyable_destroy((struct cplib_destroyable_t *) ctx);
}

int take_up_from_file(file_block_iterator_context_t *ctx) {
    ssize_t read_size;
    read_size = read(
            ctx->fd,
            (uint8_t *) ctx->buffer->mem + ctx->buffer->taken,
            ctx->buffer->size - ctx->buffer->taken
    );

    if (read_size == -1) {
        LOG_DEBUG("Failed to read from fd %d due to error %s.\n", ctx->fd, strerror(errno));
        return CPLIB_ERR_OS;
    }

    if (read_size == 0) {
        ctx->got_eof = 1;
        return CPLIB_ERR_EOF;
    }

    ctx->buffer->taken += read_size;

    ctx->allocated_iterator = cplib_allocated_block_iterator_new(ctx->buffer, ctx->iterated_size);

    if (!ctx->allocated_iterator) {
        LOG_DEBUG("Failed to allocate block iterator.\n");
        return CPLIB_ERR_MEM;
    }

    ctx->buffer->taken = 0;
    return CPLIB_ERR_SUCCESS;
}

int cplib_file_block_iterator_is_empty(cplib_block_iterator_base_t *self, int *result) {
    int ret;
    int inner_iterator_empty;
    file_block_iterator_context_t *ctx = (file_block_iterator_context_t *) self->context;


    if (ctx->allocated_iterator) {
        ret = ctx->allocated_iterator->is_empty(ctx->allocated_iterator, &inner_iterator_empty);
        if (ret != CPLIB_ERR_SUCCESS) {
            return ret;
        }

        if (!inner_iterator_empty) {
            *result = 0;
            return CPLIB_ERR_SUCCESS;
        }
    }

    // no allocated iterator or is empty
    if (ctx->got_eof) {
        *result = 1;
        return CPLIB_ERR_SUCCESS;
    }

    ret = take_up_from_file(ctx);

    if (ret == CPLIB_ERR_EOF) {
        ctx->got_eof = 1;
        *result = 1;
        return CPLIB_ERR_SUCCESS;
    }
    if (ret == CPLIB_ERR_SUCCESS) {
        *result = 0;
        return ret;
    }

    *result = 1; // some error has happened
    return ret;
}

int cplib_file_block_iterator_next(cplib_block_iterator_base_t *self, cplib_mem_chunk_t **block) {
    int ret;
    file_block_iterator_context_t *ctx;
    cplib_mem_chunk_t *partial;
    int inner_iterator_empty;

    partial = NULL;

    ctx = (file_block_iterator_context_t *) self->context;

    if (ctx->allocated_iterator) {
        ret = ctx->allocated_iterator->is_empty(ctx->allocated_iterator, &inner_iterator_empty);
        if (ret != CPLIB_ERR_SUCCESS) {
            return ret;
        }

        if (!inner_iterator_empty) {
            ret = ctx->allocated_iterator->next(ctx->allocated_iterator, (void **) block);
            if (ret != CPLIB_ERR_SUCCESS) {
                LOG_DEBUG("Failed to get next block from iterator.\n");
                return ret;
            }

            if ((*block)->taken == ctx->iterated_size) {
                return CPLIB_ERR_SUCCESS;
            }

            if (ctx->got_eof) {
                // Here we are really done.
                return CPLIB_ERR_SUCCESS;
            }

            partial_block_remaining:
            partial = *block;
        }

        // no longer has data
        cplib_destroyable_put(ctx->allocated_iterator);
        ctx->allocated_iterator = NULL;
    }

    if (partial) {
        ctx->buffer->recycle(ctx->buffer, partial->mem, partial->taken);
    }

    ret = take_up_from_file(ctx);
    if (ret == CPLIB_ERR_EOF) {
        if (partial) {
            return CPLIB_ERR_SUCCESS;
        }
        *block = NULL;
        partial = NULL;
        return CPLIB_ERR_ITER_OVERFLOW;
    }
    if (ret != CPLIB_ERR_SUCCESS) {
        return ret;
    }

    /*
     * This data will be gotten from the allocated iterator.
     * However, we cannot free before this point because we
     * first must know if we have reached EOF. In which case,
     * this would be the only remaining data.
     */
    CPLIB_PUT_IF_EXISTS(partial);
    partial = NULL;

    ret = ctx->allocated_iterator->next(ctx->allocated_iterator, (void **) block);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("Failed to get next block from iterator.\n");
        return ret;
    }

    if ((*block)->taken == ctx->iterated_size) {
        return CPLIB_ERR_SUCCESS;
    }

    goto partial_block_remaining;
}

cplib_block_iterator_base_t *cplib_file_block_iterator_new(int fd,
                                                           size_t iterated_size,
                                                           size_t buffer_size) {
    file_block_iterator_context_t *ctx;
    cplib_block_iterator_base_t *file_iterator;
    cplib_mem_chunk_t *buffer;

    file_iterator = (cplib_block_iterator_base_t *) cplib_block_iterator_new(
            (cplib_next_item_f) cplib_file_block_iterator_next,
            (cplib_empty_f) cplib_file_block_iterator_is_empty);

    if (!file_iterator) {
        LOG_DEBUG("Failed to create block iterator for file.\n");
        return NULL;
    }

    ctx = (file_block_iterator_context_t *) cplib_destroyable_new(sizeof(file_block_iterator_context_t));
    if (!ctx) {
        LOG_DEBUG("Failed to create file block iterator context for file.\n");
        cplib_destroyable_put(file_iterator);
        return NULL;
    }

    buffer = cplib_allocate_mem_chunk(buffer_size);
    if (!buffer) {
        LOG_DEBUG("Failed to allocate memory for read buffer for file.\n");
        cplib_destroyable_put(ctx);
        cplib_destroyable_put(file_iterator);
        return NULL;
    }

    file_iterator->context = (cplib_destroyable_t *) ctx;
    ctx->allocated_iterator = NULL;
    ctx->fd = fd;
    ctx->got_eof = 0;
    ctx->buffer = buffer;
    ctx->iterated_size = iterated_size;
    ctx->destroy = (cplib_independent_mutator_f) destroy_file_block_iterator_context;
    return file_iterator;
}


// ------------------------------------------------------------------------

int cplib_safe_strtoull(const char *nptr, char ** endptr, int base, unsigned long long * result) {
    unsigned long long ret;

    ret =  strtoull(nptr, endptr, base);

    if (errno != 0) {
        LOG_DEBUG("strtoull failed: %s\n", strerror(errno));
        return CPLIB_ERR_ARG;
    }

    *result = ret;

    return CPLIB_ERR_SUCCESS;
}

// ------------------------------------------------------------------------


int cplib_read_file(const char *filepath, cplib_mem_chunk_t **file_contents) {
    ssize_t ret;
    int fd;
    struct stat file_stat;
    LOG_DEBUG("Getting file_contents from file %s\n", filepath);

    fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        LOG_DEBUG("Failed to open %s due to error: %s\n", filepath, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    ret = fstat(fd, &file_stat);
    if (ret == -1) {
        LOG_DEBUG("Failed to stat %s due to error: %s\n", filepath, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    *file_contents = cplib_allocate_mem_chunk(file_stat.st_size);
    if (!*file_contents) {
        LOG_DEBUG("Failed to allocate memory for file_contents\n");
        return CPLIB_ERR_MEM;
    }

    LOG_VERBOSE("File size: %ld\n", file_stat.st_size);
    ret = read(fd, (*file_contents)->mem, file_stat.st_size);
    if (ret == -1) {
        LOG_DEBUG("Failed to read %s due to error: %s\n", filepath, strerror(errno));
        return CPLIB_ERR_FILE;
    }

    if (ret != file_stat.st_size) {
        LOG_DEBUG("Failed to read file_contents from file.\n");
    }

    (*file_contents)->taken = file_stat.st_size;

    return CPLIB_ERR_SUCCESS;
}

// ------------------------------------------------------------------------
