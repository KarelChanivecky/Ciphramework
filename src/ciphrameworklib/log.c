/**
 * Karel Chanivecky 2023.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

static int vlog(char * level, int append, const char * fmt, va_list ap) {
    char * str;
    int len_va;
    len_va = vasprintf();
}