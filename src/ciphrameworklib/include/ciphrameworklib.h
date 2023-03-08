/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_CIPHRAMEWORKLIB_H
#define SOURCES_CIPHRAMEWORKLIB_H

#include <stdlib.h>
#include <stdint.h>

#include "cplib_mem.h"

/**
 *
 * TODO
 *  IMPLEMENTATION
 *   - Key expansion
 *   - round function
 */

// ------------------------------------------------------------------------

enum cplib_base_error_codes {
    CPLIB_ERR_SUCCESS = 1,
    CPLIB_ERR_ITER_OVERFLOW,  // shouldn't have tried to continue iterating
    CPLIB_ERR_DATA_SIZE,
    CPLIB_ERR_KEY_SIZE,
    CPLIB_ERR_SIZE_MISMATCH,
    CPLIB_ERR_CIPHER,
    CPLIB_ERR_MEM,
    CPLIB_ERR_ARG,
    CPLIB_ERR_OS,
    CPLIB_ERR_FILE,
    CPLIB_ERR_EOF
};

enum cplib_block_position {
    CPLIB_BLOCK_POS_START,
    CPLIB_BLOCK_POS_CENTER,
    CPLIB_BLOCK_POS_END
};

enum cplib_proc_type {
    CPLIB_PROC_NONE,
    CPLIB_PROC_ENCRYPT,
    CPLIB_PROC_DECRYPT
};

#define CPLIB_CLOSED_FD (-2)

// ------------------------------------------------------------------------
struct cplib_cipher_base_t;

#define CPLIB_UNUSED_PARAM(param) (void)(param)


/**
 * Perform a mode transform before processing through cipher.
 * If passed processed == NULL will allocate a new chunk. Else, will recycle the chunk.
 */
typedef int (*cplib_process_f)(
        struct cplib_destroyable_t *self,
        cplib_mem_chunk_t *data,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **processed
);

typedef int (*cplib_cipher_base_init_f)(struct cplib_cipher_base_t *self, struct cplib_cipher_base_t *other);

struct cplib_cipher_base_t {
    cplib_destroyable_t;
    cplib_cipher_base_init_f initialize;
    cplib_process_f process;
};

typedef struct cplib_cipher_base_t cplib_cipher_base_t;

cplib_cipher_base_t *cplib_cipher_base_new(size_t struct_size, cplib_process_f process);

cplib_cipher_base_t *cplib_cipher_new(cplib_process_f process);

int cplib_cipher_base_destroy(cplib_cipher_base_t *cipher);

// ------------------------------------------------------------------------

struct cplib_cipher_factory_base_t;

typedef cplib_cipher_base_t *(*cplib_cipher_base_allocator_f)(struct cplib_cipher_factory_base_t* self);


struct cplib_cipher_factory_base_t {
    cplib_destroyable_t;
    cplib_cipher_base_allocator_f allocate;
    cplib_destroyable_t * context;
};

typedef struct cplib_cipher_factory_base_t cplib_cipher_factory_base_t;


cplib_cipher_factory_base_t *cplib_cipher_factory_base_new(size_t struct_size, cplib_cipher_base_allocator_f allocator);

cplib_cipher_factory_base_t *cplib_cipher_factory_new(cplib_cipher_base_allocator_f allocator);

int cplib_cipher_factory_base_destroy(cplib_cipher_factory_base_t *factory);

// ------------------------------------------------------------------------

struct cplib_cipher_provider_base_t;


struct cplib_cipher_provider_base_t {
    cplib_destroyable_t;
    cplib_next_item_f next;
};

typedef struct cplib_cipher_provider_base_t cplib_cipher_provider_base_t;

cplib_cipher_provider_base_t *cplib_cipher_provider_base_new(size_t struct_size, cplib_next_item_f next);

cplib_cipher_provider_base_t *cplib_cipher_provider_new(cplib_next_item_f next);

int cplib_cipher_provider_base_destroy(cplib_cipher_provider_base_t *provider);

// ------------------------------------------------------------------------

struct cplib_writer_base_t;

typedef int (*cplib_write_data_f)(struct cplib_writer_base_t *self, cplib_mem_chunk_t *data);

struct cplib_writer_base_t {
    cplib_destroyable_t;
    cplib_write_data_f write;
    cplib_independent_mutator_f close;
    cplib_independent_mutator_f flush;
};

typedef struct cplib_writer_base_t cplib_writer_base_t;

cplib_writer_base_t *cplib_writer_base_new(size_t struct_size, cplib_write_data_f write);

cplib_writer_base_t *cplib_writer_new(cplib_write_data_f write);

int cplib_writer_base_destroy(cplib_writer_base_t *writer);

// ------------------------------------------------------------------------

struct cplib_block_manipulator_base_t;

typedef int (*cplib_block_split_f)(struct cplib_block_manipulator_base_t *self,
                                   cplib_mem_chunk_t *data,
                                   size_t split_size,
                                   cplib_mem_chunk_t ***chunks,
                                   unsigned int *chunk_count);

typedef int (*cplib_block_join_f)(struct cplib_block_manipulator_base_t *self,
                                  cplib_mem_chunk_t **chunks,
                                  unsigned int chunk_c,
                                  cplib_mem_chunk_t **joined);

typedef int (*cplib_block_xor_f)(struct cplib_block_manipulator_base_t *self,
                                 cplib_mem_chunk_t *one,
                                 cplib_mem_chunk_t *other,
                                 cplib_mem_chunk_t **result);

struct cplib_block_manipulator_base_t {
    cplib_destroyable_t;
    cplib_block_split_f split;
    cplib_block_join_f join;
    cplib_block_xor_f xor;
};

typedef struct cplib_block_manipulator_base_t cplib_block_manipulator_base_t;


cplib_block_manipulator_base_t *
cplib_block_manipulator_base_new(size_t struct_size, cplib_block_split_f split, cplib_block_join_f join,
                                 cplib_block_xor_f xor);

cplib_block_manipulator_base_t *
cplib_block_manipulator_new(cplib_block_split_f split, cplib_block_join_f join, cplib_block_xor_f xor);

int cplib_block_manipulator_base_destroy(cplib_block_manipulator_base_t *manipulator);

// ------------------------------------------------------------------------


typedef int (*cplib_empty_f)(void *self, int * result);


struct cplib_block_iterator_base_t {
    cplib_destroyable_t;
    cplib_next_item_f next;
    cplib_empty_f is_empty;
    cplib_destroyable_t *context;
};

typedef struct cplib_block_iterator_base_t cplib_block_iterator_base_t;

cplib_block_iterator_base_t *cplib_block_iterator_base_new(size_t struct_size,
                                                           cplib_next_item_f next,
                                                           cplib_empty_f is_empty);

cplib_block_iterator_base_t *cplib_block_iterator_new(cplib_next_item_f next, cplib_empty_f is_empty);

int cplib_block_iterator_base_destroy(cplib_block_iterator_base_t *block_iterator);

// ------------------------------------------------------------------------

struct cplib_key_provider_base_t {
    struct cplib_destroyable_t;
    cplib_mem_chunk_func initialize;
    cplib_next_item_f next;
};

typedef struct cplib_key_provider_base_t cplib_key_provider_base_t;


cplib_key_provider_base_t *cplib_key_provider_base_new(size_t struct_size, cplib_next_item_f next);

cplib_key_provider_base_t *cplib_key_provider_new(cplib_next_item_f next);

int cplib_key_provider_base_destroy(cplib_key_provider_base_t *key_provider);

// ------------------------------------------------------------------------

struct cplib_key_provider_factory_base_t;

typedef cplib_key_provider_base_t *(*cplib_key_provider_allocator_f)(void);

typedef cplib_key_provider_base_t *(*cplib_key_provider_from_chunk_f)(struct cplib_key_provider_factory_base_t *self,
                                                                      cplib_mem_chunk_t *chunk);

struct cplib_key_provider_factory_base_t {
    cplib_destroyable_t;
    cplib_key_provider_allocator_f allocate;
    cplib_key_provider_from_chunk_f from;
};

typedef struct cplib_key_provider_factory_base_t cplib_key_provider_factory_base_t;


cplib_key_provider_factory_base_t *
cplib_key_provider_factory_base_new(size_t struct_size, cplib_key_provider_allocator_f allocator);

cplib_key_provider_factory_base_t *cplib_key_provider_factory_new(cplib_key_provider_allocator_f allocator);

int cplib_key_provider_factory_base_destroy(cplib_key_provider_factory_base_t *key_provider_factory);

// ------------------------------------------------------------------------

struct cplib_mode_base_t;

typedef int (*cplib_mode_output_f)(struct cplib_mode_base_t *self, cplib_mem_chunk_t *data,
                                   cplib_writer_base_t *writer);

/**
 * Perform a mode transform before processing through cipher.
 * If passed NULL will allocate a new chunk. Else, will recycle the chunk.
 */
typedef int (*cplib_mode_pre_transform_f)(
        struct cplib_mode_base_t *self,
        cplib_mem_chunk_t *data,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **out
);

/**
 * Perform a mode transform after processing through cipher.
 * If passed NULL will allocate a new chunk. Else, will recycle the chunk.
 */
typedef int (*cplib_mode_post_transform_f)(
        struct cplib_mode_base_t *self,
        cplib_mem_chunk_t *processed,
        cplib_mem_chunk_t *unpadded,
        cplib_mem_chunk_t *key,
        enum cplib_block_position position,
        cplib_mem_chunk_t **out
);

struct cplib_mode_base_t {
    cplib_destroyable_t;
    cplib_mode_pre_transform_f pre_cipher_transform;
    cplib_mode_post_transform_f post_cipher_transform;
};

typedef struct cplib_mode_base_t cplib_mode_base_t;

cplib_mode_base_t *cplib_mode_base_new(size_t struct_size,
                                       cplib_mode_pre_transform_f pre_transform,
                                       cplib_mode_post_transform_f post_transform);

cplib_mode_base_t *cplib_mode_new(cplib_mode_pre_transform_f pre_transform, cplib_mode_post_transform_f post_transform);

int cplib_mode_base_destroy(cplib_mode_base_t *mode);

// ------------------------------------------------------------------------

struct cplib_block_padder_base_t;

/**
 * Perform a mode transform before processing through cipher.
 * If passed padded_block == NULL will allocate a new chunk. Else, will recycle the chunk.
 * Same behaviour for extra_block.
 */
typedef int (*cplib_block_pad_f)(struct cplib_block_padder_base_t *self,
                                 cplib_mem_chunk_t *block,
                                 size_t key_len,
                                 cplib_mem_chunk_t **padded_block,
                                 cplib_mem_chunk_t **extra_block);

typedef int (*cplib_block_unpad_f)(
        struct cplib_block_padder_base_t *self,
        cplib_mem_chunk_t *block,
        cplib_mem_chunk_t **unpadded_block);

struct cplib_block_padder_base_t {
    cplib_destroyable_t;
    cplib_block_pad_f pad;
    cplib_block_unpad_f unpad;
};

typedef struct cplib_block_padder_base_t cplib_block_padder_base_t;

cplib_block_padder_base_t *
cplib_block_padder_base_new(size_t struct_size, cplib_block_pad_f pad, cplib_block_unpad_f unpad);

cplib_block_padder_base_t *cplib_block_padder_new(cplib_block_pad_f pad, cplib_block_unpad_f unpad);

int cplib_block_padder_base_destroy(cplib_block_padder_base_t *padder);

// ------------------------------------------------------------------------

struct cplib_cipher_driver_t;


struct cplib_cipher_driver_t {
    cplib_destroyable_t;
    size_t block_size;
    cplib_independent_mutator_f run;
    cplib_cipher_factory_base_t *cipher_factory;
    cplib_cipher_base_t *_cipher;
    cplib_mode_base_t *mode;
    cplib_writer_base_t *writer;
    cplib_key_provider_base_t *key_provider;
    cplib_block_iterator_base_t *block_iterator;
    cplib_block_padder_base_t *block_padder;
    int block_position;
};

typedef struct cplib_cipher_driver_t cplib_cipher_driver_t;

cplib_cipher_driver_t *cplib_cipher_driver_new(void);

int cplib_cipher_driver_base_destroy(cplib_cipher_driver_t *cipher_driver);

// ------------------------------------------------------------------------

//#define CPLIB_BYTE_MASK_1000_0000 0b10000000
//#define CPLIB_BYTE_MASK_1100_0000 0b11000000
//#define CPLIB_BYTE_MASK_1110_0000 0b11100000
//#define CPLIB_BYTE_MASK_1111_0000 0b11110000
//#define CPLIB_BYTE_MASK_1111_1000 0b11111000
//#define CPLIB_BYTE_MASK_1111_1100 0b11111100
//#define CPLIB_BYTE_MASK_1111_1110 0b11111110
//#define CPLIB_BYTE_MASK_1111_1111 0b11111111
//#define CPLIB_BYTE_MASK_0111_1111 0b01111111
//#define CPLIB_BYTE_MASK_0011_1111 0b00111111
//#define CPLIB_BYTE_MASK_0001_1111 0b00011111
//#define CPLIB_BYTE_MASK_0000_1111 0b00001111
//#define CPLIB_BYTE_MASK_0000_0111 0b00000111
//#define CPLIB_BYTE_MASK_0000_0011 0b00000011
//#define CPLIB_BYTE_MASK_0000_0001 0b00000001

#define CPLIB_BYTE_MASK_L 0xf0
#define CPLIB_BYTE_MASK_R 0x0f

typedef struct cplib_byte_mask_t {
    uint8_t left;
    uint8_t right;
} cplib_byte_mask_t;

#endif //SOURCES_CIPHRAMEWORKLIB_H
