/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_CPLIB_HELPER_IMPLEMENTATIONS_H
#define SOURCES_CPLIB_HELPER_IMPLEMENTATIONS_H

#include "ciphrameworklib.h"

struct cplib_keyed_key_provider_t {
    cplib_key_provider_base_t;
    cplib_mem_chunk_t *key;
};

typedef struct cplib_keyed_key_provider_t cplib_keyed_key_provider_t;

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new(size_t struct_size, cplib_next_item_f next);

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new2(cplib_next_item_f next);

int cplib_keyed_key_provider_destroy(cplib_keyed_key_provider_t *self);

// ------------------------------------------------------------------------

struct cplib_round_cipher_base_t {
    cplib_cipher_base_t;
    cplib_cipher_provider_base_t *cipher_provider;
    cplib_key_provider_factory_base_t *key_provider_factory;
    cplib_key_provider_base_t *key_provider;
};

typedef struct cplib_round_cipher_base_t cplib_round_cipher_base_t;

cplib_round_cipher_base_t *
cplib_round_cipher_base_new(size_t struct_size, cplib_cipher_provider_base_t *cipher_provider,
                            cplib_key_provider_factory_base_t *key_provider_factory);

cplib_round_cipher_base_t *cplib_round_cipher_new(cplib_cipher_provider_base_t *cipher_provider,
                                                  cplib_key_provider_factory_base_t *key_provider_factory);

int cplib_round_cipher_base_destroy(cplib_round_cipher_base_t *self);

// ------------------------------------------------------------------------

struct cplib_feistel_cipher_t;

typedef int (*cplib_feistel_round_f)(cplib_destroyable_t *self,
                                     cplib_mem_chunk_t *in,
                                     cplib_mem_chunk_t **out,
                                     cplib_mem_chunk_t *key,
                                     enum cplib_block_position block_position);

struct cplib_feistel_cipher_t {
    cplib_cipher_base_t;
    cplib_destroyable_t * round_function_self;
    cplib_feistel_round_f round_function;
    cplib_block_manipulator_base_t *block_manipulator;
};

typedef struct cplib_feistel_cipher_t cplib_feistel_cipher_t;

int cplib_feistel_cipher_encrypt(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *plaintext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **ciphertext_ptr);

int cplib_feistel_cipher_decrypt(
        cplib_feistel_cipher_t *self,
        cplib_mem_chunk_t *ciphertext,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **plaintext_ptr);


cplib_feistel_cipher_t *
cplib_feistel_cipher_new(cplib_process_f decrypt_or_encrypt_func,
                         cplib_feistel_round_f round_function,
                         cplib_destroyable_t * round_function_self,
                         cplib_block_manipulator_base_t *block_manipulator);

int cplib_feistel_cipher_destroy(cplib_feistel_cipher_t *self);

#endif //SOURCES_CPLIB_HELPER_IMPLEMENTATIONS_H
