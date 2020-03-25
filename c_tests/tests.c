#include "test_common.h"

int test_auth_token();
int test_simple();

int
main() {
    int ret = 0;

    RUN_TEST(test_auth_token);
    RUN_TEST(test_simple);

    return ret;
}

