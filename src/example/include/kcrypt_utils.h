/**
 * Karel Chanivecky 2023.
 */


#ifndef SOURCES_KCRYPT_UTILS_H
#define SOURCES_KCRYPT_UTILS_H

#include <stdlib.h>

#include "cplib_mem.h"
#include "kcrypt.h"

int kcrypt_get_available_shared_libs(char *dirname, cplib_mem_chunk_t ***lib_names, unsigned int *lib_count);

int
kcrypt_n_match_str(char **left,
                   unsigned int left_count,
                   char **right,
                   unsigned int right_count,
                   size_t max_comp);

int
kcrypt_n_match(cplib_mem_chunk_t **left,
               unsigned int left_count,
               cplib_mem_chunk_t **right,
               unsigned int right_count,
               size_t max_comp);

int
kcrypt_match(cplib_mem_chunk_t **left, unsigned int left_count, cplib_mem_chunk_t **right, unsigned int right_count);

void kcrypt_lower_case(char *str);

void kcrypt_upper_case(char *str);

int kcrypt_init_module_api(const char *api_path, kcrypt_shared_module_api_t *lib_api, void **api_handle);

int kcrypt_make_lib_path(const char * lib_dir, const char * lib_name, cplib_mem_chunk_t ** lib_path);

int kcrypt_match_sizes(size_t size, const size_t * sizes, unsigned int sizes_c);

#endif //SOURCES_KCRYPT_UTILS_H
