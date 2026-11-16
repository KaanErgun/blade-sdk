/* MIT License, copyright (c) 2026 Kaan Ergun. */
#include "package.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
    const char *ordered[] = {"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "100000000000000000000.0.0"};
    unsigned checks = 0;
    for (unsigned i = 0; i < sizeof(ordered) / sizeof(ordered[0]); ++i) {
        assert(bp_version_valid(ordered[i])); ++checks;
        assert(bp_version_compare(ordered[i], ordered[i]) == 0); ++checks;
        for (unsigned k = i + 1; k < sizeof(ordered) / sizeof(ordered[0]); ++k) {
            assert(bp_version_compare(ordered[i], ordered[k]) < 0); ++checks;
            assert(bp_version_compare(ordered[k], ordered[i]) > 0); ++checks;
        }
    }
    assert(bp_version_compare("1.0.0+first", "1.0.0+second") == 0); ++checks;
    const char *invalid[] = {"", "1", "1.0", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+", "1.0.0-a..b", "1.0.0+a..b", "1.0.0+a?"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) { assert(!bp_version_valid(invalid[i])); ++checks; }
    assert(bp_id("org.blade.hello")); ++checks;
    assert(!bp_id("../outside")); ++checks;
    assert(!bp_id("org..blade")); ++checks;
    printf("PASS %u native SemVer and identity checks\n", checks);
    return 0;
}
