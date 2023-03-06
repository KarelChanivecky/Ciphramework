//
// Created by karel on 03/03/23.
//

#ifndef SOURCES_CPLIB_LOG_H
#define SOURCES_CPLIB_LOG_H

#include <stdio.h>

#define LOG_MSG(...) fprintf(stderr, __VA_ARGS__), fflush(stderr)

#ifdef CPLIB_VERBOSE
    #define CPLIB_DEBUG
    #define LOG_VERBOSE(...) LOG_MSG(__VA_ARGS__)
#else
    #define LOG_VERBOSE(...)
#endif

#ifdef CPLIB_DEBUG
    #define LOG_DEBUG(...) (LOG_MSG(__VA_ARGS__))
#else
    #define LOG_DEBUG(...)
#endif // CPLIB_DEBUG


#endif //SOURCES_CPLIB_LOG_H

