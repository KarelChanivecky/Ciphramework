/**
 * Karel Chanivecky 2023.
 */

#include <dirent.h>
#include <dc_utils/dlinked_list.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>

#include "ciphrameworklib.h"
#include "cplib_log.h"
#include "kcrypt_utils.h"
#include "kcrypt.h"

int kcrypt_get_available_shared_libs(char *dirname, cplib_mem_chunk_t ***lib_names, unsigned int *lib_count) {
    DIR *directory;
    struct dirent *directory_entry;
    dlinked_list *lib_name_list;
    unsigned int dir_entry_name_len;
    cplib_mem_chunk_t *lib;
    int ret;

    LOG_DEBUG("Getting available shared libraries in dir_pointer: %s\n", dirname);

    lib_name_list = dlinked_create_list();
    if (lib_name_list == NULL) {
        LOG_MSG("Out of memory\n");
        return CPLIB_ERR_MEM;
    }

    directory = opendir(dirname);
    if (directory == NULL) {
        LOG_MSG("Could not open directory: %s\n", dirname);
        return CPLIB_ERR_OS;
    }

    directory_entry = readdir(directory);

    while (directory_entry != NULL) {
        if (directory_entry->d_type == DT_DIR) {
            continue;
        }

        if (directory_entry->d_name[0] == '.') {
            continue;
        }
        dir_entry_name_len = strnlen(directory_entry->d_name, NAME_MAX);

        if (strncmp(directory_entry->d_name + dir_entry_name_len - 3, ".so", dir_entry_name_len) != 0) {
            continue;
        }

        LOG_DEBUG("Found shared library: %s\n", directory_entry->d_name);

        lib = cplib_mem_chunk_str_new(directory_entry->d_name);

        if (dlinked_push(lib_name_list, lib) != SUCCESS) {
            return CPLIB_ERR_MEM;
        }

        directory_entry = readdir(directory);
    }

    if (errno != 0) {
        LOG_MSG("Could not read directory: %s\n", dirname);
        return CPLIB_ERR_OS;
    }

    closedir(directory);

    if (dlinked_to_pointer(lib_name_list, (void ***) lib_names) != SUCCESS) {
        ret = CPLIB_ERR_MEM;
    } else {
        ret = SUCCESS;
    }

    dlinked_free_list(&lib_name_list);
    return ret;
}

void kcrypt_lower_case(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] += 'a' - 'A';
        }
    }
}

void kcrypt_upper_case(char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] -= 'a' - 'A';
        }
    }
}

int kcrypt_caseless_n_cmp(const char *str1, const char *str2, size_t n) {
    char left_char;
    char right_char;

    for (size_t i = 0; i < n; i++) {
        left_char = str1[i];
        right_char = str2[i];

        if (left_char >= 'A' && left_char <= 'Z') {
            left_char += 'a' - 'A';
        }

        if (right_char >= 'A' && right_char <= 'Z') {
            right_char += 'a' - 'A';
        }

        if (left_char < right_char) {
            return 1;
        }

        if (left_char > right_char) {
            return -1;
        }
    }

    return 0;
}


int
kcrypt_n_match_str(char **left,
                   unsigned int left_count,
                   char **right,
                   unsigned int right_count,
                   size_t max_comp) {
    size_t min_size;
    size_t left_len;
    size_t right_len;
    char *left_str;
    char *right_str;


    for (unsigned int left_i = 0; left_i < left_count; left_i++) {
        // left_i = left_i + 1
        left_str = left[left_i];
        left_len = strnlen(left_str, max_comp);
        for (unsigned int right_i = 0; right_i < right_count; right_i++) {
            right_str = right[right_i];
            right_len = strnlen(right_str, max_comp);
            min_size = left_len < right_len ? left_len : right_len;
            min_size = min_size < max_comp ? min_size : max_comp;

            if (kcrypt_caseless_n_cmp(left_str, right_str, min_size) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

int
kcrypt_n_match(cplib_mem_chunk_t **left,
               unsigned int left_count,
               cplib_mem_chunk_t **right,
               unsigned int right_count,
               size_t max_comp) {
    size_t min_size;
    cplib_mem_chunk_t * left_str;
    cplib_mem_chunk_t * right_str;


    for (unsigned int left_i = 0; left_i < left_count; left_i++) {
        left_str = left[left_i];
        for (unsigned int right_i = 0; right_i < right_count; right_i++) {
            right_str = right[right_i];
            min_size = left_str->size < right_str->size? left_str->size : right_str->size;
            min_size = min_size < max_comp? min_size : max_comp;

            if (kcrypt_caseless_n_cmp(left_str->mem, right_str->mem, min_size) == 0) {
                return 1;
            }
        }
    }

    return 0;
}

int
kcrypt_match(cplib_mem_chunk_t **left, unsigned int left_count, cplib_mem_chunk_t **right, unsigned int right_count) {
    return kcrypt_n_match(left, left_count, right, right_count, UINT64_MAX);
}

int open_lib(const char *lib_name, void **init_func, void **library_api_handle) {

    *library_api_handle = dlopen(lib_name, RTLD_LAZY);
    if (library_api_handle == NULL) {
        LOG_MSG("Could not load library: %s; %s\n", lib_name, dlerror());
        return CPLIB_ERR_OS;
    }

    dlerror();
    *init_func = dlsym(*library_api_handle, KCRYPT_LIB_MODULE_INIT_FUNCTION_NAME);

    if (*init_func == NULL) {
        LOG_MSG("Could not load library: %s; %s\n", lib_name, dlerror());
        return CPLIB_ERR_OS;
    }

    LOG_DEBUG("Loaded library: %s\n", lib_name);
    return CPLIB_ERR_SUCCESS;
}

int kcrypt_init_module_api(const char *api_path, kcrypt_shared_module_api_t *lib_api, void **api_handle) {
    int ret;
    kcrypt_lib_api_init_f api_init_func;

    ret = open_lib(api_path, (void **) &api_init_func, api_handle);
    if (ret != CPLIB_ERR_SUCCESS) {
        return ret;
    }

    return (*api_init_func)(lib_api);
}

int kcrypt_make_lib_path(const char * lib_dir, const char * lib_name, cplib_mem_chunk_t ** lib_path) {
    cplib_mem_chunk_t * path;
    size_t dir_len = strlen(lib_dir);
    size_t lib_name_len = strlen(lib_name);

    path = cplib_allocate_mem_chunk(dir_len + lib_name_len + 2);
    if (path == NULL) {
        LOG_MSG("Could not allocate memory for path\n");
        return CPLIB_ERR_MEM;
    }

    path->append(path, lib_dir, dir_len);
    path->append(path, "/", 1);
    path->append(path, lib_name, lib_name_len);
    path->append(path, "\0", 1);

    *lib_path = path;

    return CPLIB_ERR_SUCCESS;
}

int kcrypt_match_sizes(size_t size, const size_t * sizes, unsigned int sizes_c) {
    for (unsigned int i = 0; i < sizes_c; i++) {
        if (size == sizes[i]) {
            return 1;
        }
    }

    return 0;
}
