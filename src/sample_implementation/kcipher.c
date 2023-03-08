/**
 * Karel Chanivecky 2023.
 */


#ifdef KCRYPT_KCIPHER_CIPHER

#include "kcipher.h"
#include "xor_cipher.h"
#include "cplib_utils.h"
#include "cplib_log.h"


int xor_cipher_proc_function(cplib_destroyable_t *base_self,
                             cplib_mem_chunk_t *data,
                             cplib_mem_chunk_t *key,
                             enum cplib_block_position position,
                             cplib_mem_chunk_t **processed_ptr) {
    CPLIB_UNUSED_PARAM(base_self);
    CPLIB_UNUSED_PARAM(position);
    int ret;
    uint8_t temp;
    uint8_t *mem;
    cplib_block_manipulator_base_t *block_manipulator;
    cplib_mem_chunk_t *processed;

    block_manipulator = cplib_simple_block_manipulator_new();
    if (!*processed_ptr) {
        *processed_ptr = cplib_allocate_mem_chunk(key->taken);
        if (!*processed_ptr) {
            LOG_MSG("Failed to allocate memory for processed data\n");
            ret = CPLIB_ERR_MEM;
            goto cleanup;
        }
    }

    processed = *processed_ptr;

    if (processed->size < key->taken) {
        LOG_MSG("Passed processed buffer is smaller than needed. given %zu < needed %zu\n", processed->size,
                key->taken);
        ret = CPLIB_ERR_SIZE_MISMATCH;
        goto cleanup;
    }

    mem = data->mem;
    temp = mem[0];
    mem[0] = mem[2];
    mem[0] = mem[2];
    mem[2] = mem[1];
    mem[1] = temp;
    ret = block_manipulator->xor(block_manipulator, data, key, processed_ptr);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to xor data\n");
        goto cleanup;
    }

    ret = CPLIB_ERR_SUCCESS;

    cleanup:
    CPLIB_PUT_IF_EXISTS(block_manipulator);
    return ret;
}

int kcipher_round_function(cplib_destroyable_t *round_f_self,
                           cplib_mem_chunk_t *data,
                           cplib_mem_chunk_t *key,
                           enum cplib_block_position position,
                           cplib_mem_chunk_t **processed_ptr) {
    CPLIB_UNUSED_PARAM(round_f_self);
    return xor_cipher_proc_function(round_f_self, data, key, position, processed_ptr);
}


//cplib_cipher_factory_base_t *cipher_get_cipher_factory(enum cplib_proc_type process_type) {
//    return cplib_feistel_cipher_factory_new(process_type, kcipher_round_function, NULL);
//}

struct kcipher_factory_context_t;

struct kcipher_factory_context_t {
    cplib_destroyable_t;
    enum cplib_proc_type process_type;
};

typedef struct kcipher_factory_context_t kcipher_factory_context_t;

int destroy_kcipher_factory_context(struct kcipher_factory_context_t *self) {
    LOG_VERBOSE("Destroying kcipher_factory_context_t %p\n", (void *) self);
    self->process_type = CPLIB_PROC_NONE;
    return cplib_destroyable_destroy((struct cplib_destroyable_t *) self);
}


cplib_cipher_base_t *allocate_kcipher(cplib_cipher_factory_base_t *self) {
    CPLIB_UNUSED_PARAM(self);
    cplib_cipher_base_t *feistel = NULL;
    cplib_cipher_provider_base_t *cipher_provider = NULL;
    cplib_key_provider_factory_base_t *key_provider_factory = NULL;
    cplib_cipher_base_t *round_cipher = NULL;
    cplib_block_manipulator_base_t *block_manipulator = NULL;

    block_manipulator = cplib_simple_block_manipulator_new();
    if (!block_manipulator) {
        LOG_MSG("Failed to allocate block manipulator\n");
        goto error_cleanup;
    }

    feistel = (cplib_cipher_base_t *) cplib_feistel_cipher_new(kcipher_round_function,
                                                               NULL,
                                                               block_manipulator);
    cplib_destroyable_put(block_manipulator);
    if (!feistel) {
        LOG_MSG("Failed to allocate cipher\n");
        goto error_cleanup;
    }

    key_provider_factory = cplib_key_provider_factory_new(
            (cplib_key_provider_allocator_f) cplib_keyed_key_provider_new3);


    round_cipher = (cplib_cipher_base_t *) cplib_round_cipher_new2(feistel, 8, key_provider_factory);

    return round_cipher;
    error_cleanup:
    CPLIB_PUT_IF_EXISTS(feistel);
    CPLIB_PUT_IF_EXISTS(key_provider_factory);
    CPLIB_PUT_IF_EXISTS(cipher_provider);
    CPLIB_PUT_IF_EXISTS(round_cipher);
    return NULL;
}

cplib_cipher_factory_base_t *cipher_get_cipher_factory(enum cplib_proc_type process_type) {
//    return cplib_feistel_cipher_factory_new(process_type, kcipher_round_function, NULL);
    cplib_cipher_factory_base_t *kcipher_factory;
    kcipher_factory_context_t *ctx;

    kcipher_factory = cplib_cipher_factory_new(allocate_kcipher);
    if (!kcipher_factory) {
        return NULL;
    }

    ctx = (kcipher_factory_context_t *) cplib_destroyable_new(sizeof(kcipher_factory_context_t));
    if (!ctx) {
        cplib_destroyable_put(kcipher_factory);
        return NULL;
    }

    ctx->process_type = process_type;
    ctx->destroy = (cplib_independent_mutator_f) destroy_kcipher_factory_context;

    kcipher_factory->context = (cplib_destroyable_t *) ctx;
    return kcipher_factory;
}

int expand_key(cplib_mem_chunk_t *key, cplib_mem_chunk_t **expanded_key) {
    (*expanded_key)->recycle(*expanded_key, key->mem, key->taken);
    return CPLIB_ERR_SUCCESS;
}


int kcipher_key_provider_initialize(cplib_keyed_key_provider_t *self, cplib_mem_chunk_t *root_key) {
    int ret;
    cplib_mem_chunk_t *expanded_key;

    if (root_key->taken != sizeof(uint32_t)) {
        LOG_MSG("This cipher requires a %zub key\n", sizeof(uint32_t) * 8);
        return CPLIB_ERR_KEY_SIZE;
    }

    expanded_key = cplib_allocate_mem_chunk(sizeof(uint64_t));
    if (!expanded_key) {
        LOG_MSG("Failed to allocate memory for expanded key\n");
        return CPLIB_ERR_MEM;
    }

    ret = expand_key(root_key, &expanded_key);
    if (ret != CPLIB_ERR_SUCCESS) {
        LOG_MSG("Failed to expand key\n");
        return ret;
    }

    self->key = expanded_key;

    return CPLIB_ERR_SUCCESS;
}

cplib_key_provider_base_t *cipher_allocate_key_provider(void) {
    cplib_key_provider_base_t *key_provider = (cplib_key_provider_base_t *) cplib_keyed_key_provider_new3();
    if (!key_provider) {
        return NULL;
    }

    key_provider->initialize = (cplib_mem_chunk_func) kcipher_key_provider_initialize;

    return key_provider;
}

cplib_key_provider_factory_base_t *cipher_get_key_provider_factory(void) {
    return cplib_key_provider_factory_new(cipher_allocate_key_provider);
}


size_t cipher_block_to_key_ratio(void) {
    return 2;
}

#endif // KCRYPT_KCIPHER_CIPHER
