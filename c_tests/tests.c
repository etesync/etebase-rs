// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

#include "test_common.h"

int test_auth_token();
int test_simple();
int test_errors();
int test_user_info();

int
main() {
    int ret = 0;

    RUN_TEST(test_auth_token);
    RUN_TEST(test_simple);
    RUN_TEST(test_errors);
    RUN_TEST(test_user_info);

    return ret;
}

