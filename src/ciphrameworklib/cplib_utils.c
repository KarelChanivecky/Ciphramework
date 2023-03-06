/**
 * Karel Chanivecky 2023.
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "cplib_utils.h"
#include "cplib_log.h"


int cplib_keyed_key_provider_default_next(void *g_self, void **key) {
    cplib_keyed_key_provider_t *self = (cplib_keyed_key_provider_t *) g_self;
    *key = self->key;
    cplib_destroyable_hold(key);
    return CPLIB_ERR_SUCCESS;
}

int cplib_keyed_key_provider_destroy(cplib_keyed_key_provider_t *self) {
    cplib_destroyable_put(self->key);
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

        cplib_destroyable_put(cipher);
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
    ciphertext_halves[0] = cplib_allocate_mem_chunk(plaintext->size / 2);
    ciphertext_halves[1] = cplib_allocate_mem_chunk(plaintext->size / 2);
    round_function_result = cplib_allocate_mem_chunk(plaintext->size / 2);
    unsigned int unused;

    if (!ciphertext_halves[0] || !ciphertext_halves[1] || !round_function_result) {
        LOG_DEBUG("Failed to allocate memory for encryption. Out of memory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    ret = self->block_manipulator->split(self->block_manipulator, plaintext, plaintext->size / 2,
                                         (cplib_mem_chunk_t ***) &plaintext_halves,
                                         &unused);
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

    ret = self->block_manipulator->xor(self->block_manipulator, round_function_result, plaintext_halves[0],
                                       &ciphertext_halves[1]);

    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_DEBUG("XOR failed. ret=%d\n", ret);
        goto cleanup;
    }

    ret = self->block_manipulator->join(self->block_manipulator, ciphertext_halves, 2, ciphertext_ptr);

    cleanup:

    for (int i = 0; i < 2; i++) {
        CPLIB_PUT_IF_EXISTS(plaintext_halves[i]);
        CPLIB_PUT_IF_EXISTS(ciphertext_halves[i]);
    }
    CPLIB_PUT_IF_EXISTS(round_function_result);

    return ret;
}

int cplib_feistel_cipher_decrypt(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *ciphertext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **plaintext_ptr) {

    int ret;
    unsigned int unused;
    cplib_mem_chunk_t *ciphertext_halves[2] = {0}; // allocated by split
    cplib_mem_chunk_t *plaintext_halves[2] = {0};
    cplib_mem_chunk_t *round_function_result;
    plaintext_halves[0] = cplib_allocate_mem_chunk(ciphertext->size / 2);
    plaintext_halves[1] = cplib_allocate_mem_chunk(ciphertext->size / 2);
    round_function_result = cplib_allocate_mem_chunk(ciphertext->size / 2);

    if (!ciphertext_halves[0] || !ciphertext_halves[1] || !round_function_result) {
        LOG_DEBUG("Failed to allocate memory for encryption. Out of memory\n");
        ret = CPLIB_ERR_MEM;
        goto cleanup;
    }

    plaintext_halves[0]->taken = plaintext_halves[0]->size;
    plaintext_halves[1]->taken = plaintext_halves[1]->size;
    round_function_result->taken = round_function_result->size;


    ret = self->block_manipulator->split(self->block_manipulator, ciphertext, ciphertext->size / 2,
                                         (cplib_mem_chunk_t ***) &ciphertext_halves, &unused);
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

// ------------------------------------------------------------------------

int provide_next_cipher(cplib_same_cipher_provider_t *self, cplib_cipher_base_t **cipher) {
    if (!self->provide_count) {
        *cipher = NULL;
        return CPLIB_ERR_SUCCESS;
    }

    *cipher = self->cipher;
    cplib_destroyable_hold(self->cipher);
    return CPLIB_ERR_SUCCESS;
}

int cplib_same_cipher_provider_destroy(cplib_same_cipher_provider_t *self) {
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

    return cipher_provider;
}

// ------------------------------------------------------------------------

int cplib_block_split(cplib_block_manipulator_base_t *block_manipulator,
                      cplib_mem_chunk_t *block,
                      size_t split_size,
                      cplib_mem_chunk_t ***chunks_ptr,
                      unsigned int *chunk_count_ptr) {
    unsigned int chunk_count;
    unsigned int chunk_index;
    uint8_t *from_block_data;
    uint8_t *to_block_data;
    cplib_mem_chunk_t **chunks;
    cplib_mem_chunk_t *chunk;

    from_block_data = block->mem;
    chunk_count = block->taken / split_size;
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
        to_block_data[i % split_size] = from_block_data[i];
        chunk->taken++;
    }

    return CPLIB_ERR_SUCCESS;
}

int cplib_block_join(cplib_block_manipulator_base_t *block_manipulator,
                     cplib_mem_chunk_t **chunks,
                     unsigned int chunk_count,
                     cplib_mem_chunk_t **block_ptr) {

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
        }
    }

    return CPLIB_ERR_SUCCESS;
}

int cplib_block_xor(struct cplib_block_manipulator_base_t *self,
                    cplib_mem_chunk_t *one,
                    cplib_mem_chunk_t *other,
                    cplib_mem_chunk_t **result_ptr) {

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
    if (result->taken != one->taken) {
        LOG_DEBUG("Passed result block size does not match to operands. %zu!= %zu\n", result->taken, one->taken);
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

    cplib_mem_chunk_t *padded;
    cplib_mem_chunk_t *extra;
    cplib_mem_chunk_t *to_pad;
    size_t pad_len;

    LOG_VERBOSE("Padding block of %zuB\n ", data->taken);

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
        LOG_VERBOSE("Padding block because : %zu\n", data->taken);
        memcpy(padded->mem, data->mem, data->taken);
        padded->taken = data->taken;
        to_pad = padded;
    } else {
        LOG_VERBOSE("Padding extra block because pad_len= %zu\n", pad_len);

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

        to_pad = extra;
    }

    memset((uint8_t *) to_pad->mem + to_pad->taken, (uint8_t) pad_len, pad_len);
    to_pad->taken += pad_len;

    return CPLIB_ERR_SUCCESS;
}

int pkcs5_block_unpad(cplib_block_padder_base_t *self, cplib_mem_chunk_t *data, cplib_mem_chunk_t **unpadded_ptr) {
    cplib_mem_chunk_t *unpadded;
    size_t unpadded_block_len;
    uint8_t *data_mem;

    data_mem = data->mem;
    unpadded_block_len = data_mem[data->taken - 1];

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

    LOG_VERBOSE("Unpadded block of length: %zu\n", unpadded_block_len);
    return CPLIB_ERR_SUCCESS;
}

cplib_block_padder_base_t *cplib_pkcs5_padder_new(enum cplib_proc_type process_type) {
    if (process_type == CPLIB_PROC_ENCRYPT) {
        return cplib_block_padder_new(pkcs5_block_pad, NULL);
    }

    return cplib_block_padder_new(NULL, pkcs5_block_unpad);
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
    for (unsigned int i = 0; i < ctx->chunk_count; i++) {
        cplib_destroyable_put(ctx->chunks[i]);
    }
    cplib_free(ctx->chunks);
    cplib_free(ctx);
    return CPLIB_ERR_SUCCESS;
}


int block_allocated_iterator_next(cplib_block_iterator_base_t *self, cplib_mem_chunk_t **next_ptr) {
    allocated_block_iterator_context_t *ctx = (allocated_block_iterator_context_t *) self;

    if (self->is_empty(self)) {
        return CPLIB_ERR_ITER_STOP;
    }

    *next_ptr = ctx->chunks[ctx->next_chunk];
    ctx->next_chunk++;
    return CPLIB_ERR_SUCCESS;
}

int block_allocated_iterator_is_empty(cplib_block_iterator_base_t *self) {
    allocated_block_iterator_context_t *ctx = (allocated_block_iterator_context_t *) self->context;
    return ctx->next_chunk >= ctx->chunk_count;
}


cplib_block_iterator_base_t *cplib_allocated_block_iterator_new(cplib_mem_chunk_t *data, size_t iterated_size) {
    int ret;
    cplib_block_iterator_base_t *block_iterator;
    allocated_block_iterator_context_t *ctx;

    block_iterator = cplib_block_iterator_new(
            (cplib_next_item_f) block_allocated_iterator_next,
            (cplib_empty_f) block_allocated_iterator_is_empty);

    if (!block_iterator) {
        LOG_DEBUG("Failed to allocate block iterator\n");
        return NULL;
    }

    block_iterator->destroy = (cplib_independent_mutator_f) destroy_allocated_block_iterator_context;
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
    return block_iterator;
}

// ------------------------------------------------------------------------

#define CLOSED_FD (-2)

int file_writer_write(cplib_file_writer_t *self, cplib_mem_chunk_t *data) {
    ssize_t ret;

    if (self->fd == CLOSED_FD) {
        self->fd = open((char *) self->file_path->mem, O_WRONLY | O_CREAT | O_APPEND);
        if (self->fd == -1) {
            LOG_MSG("Failed to open file %s due to error: %s\n", (char *) self->file_path->mem, strerror(errno));
            self->fd = CLOSED_FD;
            return CPLIB_ERR_OS;
        }
    }

    ret = write(self->fd, data->mem, data->size);
    if (ret == -1) {
        LOG_MSG("Failed to write to file %s due to error: %s\n", (char *) self->file_path->mem, strerror(errno));
        return CPLIB_ERR_OS;
    }

    if ((size_t) ret != data->size) {
        LOG_MSG("Incomplete write to file %s. written: %zd < to write: %zu\n", (char *) self->file_path->mem, ret,
                data->size);
        return CPLIB_ERR_OS;
    }

    return CPLIB_ERR_SUCCESS;
}

int file_writer_close(cplib_file_writer_t *self) {
    int ret;
    if (self->fd != CLOSED_FD) {
        return CPLIB_ERR_SUCCESS;
    }

    ret = close(self->fd);
    self->fd = CLOSED_FD;

    if (ret == -1) {
        LOG_MSG("Failed to close file %s due to error: %s\n", (char *) self->file_path->mem, strerror(errno));
        return CPLIB_ERR_OS;
    }

    return CPLIB_ERR_SUCCESS;
}

int file_writer_destroy(cplib_file_writer_t *self) {
    int ret;

    cplib_destroyable_put(self->file_path);
    ret = self->close(self);

    if (ret == CPLIB_ERR_SUCCESS) {
        return ret;
    }

    return cplib_writer_base_destroy((cplib_writer_base_t *) self);
}


cplib_file_writer_t *cplib_file_writer_new(cplib_mem_chunk_t *file_path) {
    cplib_file_writer_t *writer = (cplib_file_writer_t *)
            cplib_writer_base_new(sizeof(cplib_file_writer_t), (cplib_write_data_f) file_writer_write);

    writer->fd = CLOSED_FD;
    writer->file_path = file_path;
    writer->destroy = (cplib_independent_mutator_f) file_writer_destroy;
    return writer;
}

// ------------------------------------------------------------------------

struct file_block_iterator_context_t {
    cplib_destroyable_t;
    cplib_mem_chunk_t *file_path;
    cplib_mem_chunk_t *buffer;
    int fd;
    int got_eof;
    size_t iterated_size;
    cplib_block_iterator_base_t *allocated_iterator;
};

typedef struct file_block_iterator_context_t file_block_iterator_context_t;

int destroy_file_block_iterator_context(file_block_iterator_context_t *ctx) {
    cplib_destroyable_put(ctx->file_path);
    if (ctx->fd != CLOSED_FD) {
        close(ctx->fd);
        ctx->fd = CLOSED_FD;
    }
    ctx->got_eof = 0;
    return ctx->allocated_iterator->destroy(ctx->allocated_iterator);
}


int cplib_file_block_iterator_is_empty(cplib_block_iterator_base_t *self) {
    file_block_iterator_context_t *ctx = (file_block_iterator_context_t *) self->context;
    return ctx->got_eof && ctx->allocated_iterator && ctx->allocated_iterator->is_empty(ctx->allocated_iterator);
}

int cplib_file_block_iterator_next(cplib_block_iterator_base_t *self, cplib_mem_chunk_t **block) {
    int ret;
    ssize_t read_size;
    file_block_iterator_context_t *ctx;
    cplib_mem_chunk_t *partial;

    ctx = (file_block_iterator_context_t *) self->context;

    if (ctx->allocated_iterator) {
        if (!ctx->allocated_iterator->is_empty(ctx->allocated_iterator)) {
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

    if (ctx->fd == CLOSED_FD) {
        ctx->fd = open(ctx->file_path->mem, O_RDONLY);
        if (ctx->fd == -1) {
            LOG_DEBUG("Failed to open file %s due to error %s.\n", (char *) ctx->file_path->mem, strerror(errno));
            return CPLIB_ERR_OS;
        }
    }

    if (partial) {
        memcpy(ctx->buffer->mem, partial->mem, partial->taken);
        ctx->buffer->taken = partial->taken;
    }

    read_size = read(
            ctx->fd,
            (uint8_t *) ctx->buffer->mem + ctx->buffer->taken,
            ctx->buffer->size - ctx->buffer->taken
    );

    if (read_size == -1) {
        LOG_DEBUG("Failed to read from file %s due to error %s.\n", (char *) ctx->file_path->mem, strerror(errno));
        return CPLIB_ERR_OS;
    }

    if (read_size == 0) {
        ctx->got_eof = 1;
        if (partial) {
            return CPLIB_ERR_SUCCESS;
        }

        return CPLIB_ERR_ITER_STOP;
    }

    cplib_destroyable_put(partial);
    *block = NULL;
    partial = NULL;

    ctx->buffer->taken += read_size;

    ctx->allocated_iterator = cplib_allocated_block_iterator_new(ctx->buffer, ctx->iterated_size);
    if (!ctx->allocated_iterator) {
        LOG_DEBUG("Failed to allocate block iterator.\n");
        return CPLIB_ERR_MEM;
    }

    ctx->buffer->taken = 0;

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

cplib_block_iterator_base_t *cplib_file_block_iterator_new(cplib_mem_chunk_t *file_path,
                                                           size_t iterated_size,
                                                           size_t buffer_size) {
    file_block_iterator_context_t *ctx;
    cplib_block_iterator_base_t *file_iterator;
    cplib_block_iterator_base_t *allocated_iterator;
    cplib_mem_chunk_t *buffer;

    file_iterator = (cplib_block_iterator_base_t *) cplib_block_iterator_new(
            (cplib_next_item_f) cplib_file_block_iterator_next,
            (cplib_empty_f) cplib_file_block_iterator_is_empty);

    if (!file_iterator) {
        LOG_DEBUG("Failed to create block iterator for file %s\n", (char *) file_path->mem);
        return NULL;
    }

    ctx = (file_block_iterator_context_t *) cplib_destroyable_new(sizeof(file_block_iterator_context_t));
    if (!ctx) {
        LOG_DEBUG("Failed to create file block iterator context for file %s\n", (char *) file_path->mem);
        cplib_destroyable_put(file_iterator);
        return NULL;
    }

    buffer = cplib_allocate_mem_chunk(buffer_size);
    if (!buffer) {
        LOG_DEBUG("Failed to allocate memory for read buffer for file %s\n", (char *) file_path->mem);
        cplib_destroyable_put(ctx);
        cplib_destroyable_put(file_iterator);
        return NULL;
    }

    file_iterator->context = (cplib_destroyable_t *) ctx;
    ctx->allocated_iterator = NULL;
    ctx->file_path = file_path;
    ctx->fd = CLOSED_FD;
    ctx->got_eof = 0;
    ctx->buffer = buffer;
    ctx->iterated_size = iterated_size;
    ctx->destroy = (cplib_independent_mutator_f) destroy_file_block_iterator_context;
    return file_iterator;
}


// ------------------------------------------------------------------------

