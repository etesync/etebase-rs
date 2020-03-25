#ifndef _TEST_COMMON_H
#define _TEST_COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "../target/etesync.h"


#define fail_if(expr) \
    do { \
        if (expr) { \
            fprintf(stderr, "%s:%d: Failure '"#expr"' occurred.\n", __func__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#define assert_str_eq(str1, str2) \
    do { \
        const char *a = str1, *b = str2; \
        if (strcmp(a, b)) { \
            fprintf(stderr, "%s:%d: Falilure: '%s' != '%s'.\n", __func__, __LINE__, a, b); \
            exit(1); \
        } \
    } while (0)

#define assert_int_eq(num1, num2) \
    do { \
        const int a = num1, b = num2; \
        if (a != b) { \
            fprintf(stderr, "%s:%d: Falilure: '%d' != '%d'.\n", __func__, __LINE__, a, b); \
            exit(1); \
        } \
    } while (0)

#define RUN_TEST(test) \
    do { \
        fprintf(stderr, "> Starting test: %s\n", #test); \
        ret = ret || test(); \
        fprintf(stderr, "= Finished test: %s\n", #test); \
    } while(0)


#endif
