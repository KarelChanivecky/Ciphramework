/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_KCIPHER_H
#define SOURCES_KCIPHER_H

#include "ciphrameworklib.h"

size_t cipher_block_to_key_ratio(void);

cplib_cipher_factory_base_t *cipher_get_cipher_factory(enum cplib_proc_type process_type);

cplib_key_provider_base_t * cipher_allocate_key_provider(void);

cplib_key_provider_factory_base_t * cipher_get_key_provider_factory(void);

#endif //SOURCES_KCIPHER_H
