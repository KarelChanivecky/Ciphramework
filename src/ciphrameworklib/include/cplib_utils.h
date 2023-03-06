/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_CPLIB_UTILS_H
#define SOURCES_CPLIB_UTILS_H

#include "ciphrameworklib.h"

struct cplib_keyed_key_provider_t {
    cplib_key_provider_base_t;
    cplib_mem_chunk_t *key;
};

typedef struct cplib_keyed_key_provider_t cplib_keyed_key_provider_t;

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new(size_t struct_size, cplib_next_item_f next);

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new2(cplib_next_item_f next);

cplib_keyed_key_provider_t *cplib_keyed_key_provider_new3(void);

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

cplib_round_cipher_base_t *cplib_round_cipher_new2(cplib_cipher_base_t *cipher,
                                                   int provide_count,
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
    cplib_destroyable_t *round_function_self;
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
                         cplib_destroyable_t *round_function_self,
                         cplib_block_manipulator_base_t *block_manipulator);

int cplib_feistel_cipher_destroy(cplib_feistel_cipher_t *self);

// ------------------------------------------------------------------------

struct cplib_same_cipher_provider_t;

struct cplib_same_cipher_provider_t {
    cplib_cipher_provider_base_t;
    cplib_cipher_base_t *cipher;
    unsigned int provide_count;
};

typedef struct cplib_same_cipher_provider_t cplib_same_cipher_provider_t;

cplib_same_cipher_provider_t *cplib_same_cipher_provider_new(cplib_cipher_base_t *cipher, int provide_count);

int cplib_same_cipher_provider_destroy(cplib_same_cipher_provider_t *self);

// ------------------------------------------------------------------------

// use these with block_manipulator
int cplib_block_split(cplib_block_manipulator_base_t *block_manipulator,
                      cplib_mem_chunk_t *block,
                      size_t split_size,
                      cplib_mem_chunk_t ***chunks,
                      unsigned int *chunk_count);

int cplib_block_join(cplib_block_manipulator_base_t *block_manipulator,
                     cplib_mem_chunk_t **chunks,
                     unsigned int chunk_count,
                     cplib_mem_chunk_t **block);

int cplib_block_xor(struct cplib_block_manipulator_base_t *self,
                    cplib_mem_chunk_t *one,
                    cplib_mem_chunk_t *other,
                    cplib_mem_chunk_t **result_ptr);

cplib_block_manipulator_base_t *cplib_simple_block_manipulator_new(void);

// ------------------------------------------------------------------------

cplib_block_padder_base_t *cplib_pkcs5_padder_new(enum cplib_proc_type process_type);

// ------------------------------------------------------------------------

cplib_block_iterator_base_t *cplib_allocated_block_iterator_new(cplib_mem_chunk_t * data, size_t iterated_size);

// ------------------------------------------------------------------------

struct cplib_file_writer_t;

struct cplib_file_writer_t {
    cplib_writer_base_t;
    cplib_mem_chunk_t *file_path;
    int fd;
};

typedef struct cplib_file_writer_t cplib_file_writer_t;

cplib_file_writer_t *cplib_file_writer_new(cplib_mem_chunk_t *file_path);

int file_writer_destroy(cplib_file_writer_t *self);

// ------------------------------------------------------------------------

cplib_block_iterator_base_t *cplib_file_block_iterator_new(cplib_mem_chunk_t *file_path,
                                                           size_t iterated_size,
                                                           size_t buffer_size);

#endif //SOURCES_CPLIB_UTILS_H
