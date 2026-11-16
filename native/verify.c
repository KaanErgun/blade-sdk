/* MIT License, copyright (c) 2026 Kaan Ergun. */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "package.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) { fprintf(stderr, "usage: blade-verify PACKAGE TRUSTED-SPKI.der [--allow-root]\n"); return 2; }
    int root = argc == 4 && !strcmp(argv[3], "--allow-root");
    if (argc == 4 && !root) return 2;
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    int key = open(argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    unsigned char der[45]; ssize_t bytes = key < 0 ? -1 : read(key, der, sizeof(der));
    if (key >= 0) close(key);
    struct bp_package *p = calloc(1, sizeof(*p));
    int result = !p || fd < 0 || bytes != 44 || bp_read(fd, p) < 0 || bp_verify(p, der, (size_t)bytes, root) < 0;
    if (fd >= 0) close(fd);
    if (result) fprintf(stderr, "blade-verify: %s\n", bp_error());
    else printf("{\"id\":\"%s\",\"version\":\"%s\",\"sha256\":\"%s\",\"files\":%zu}\n", p->id, p->version, p->hash, p->count);
    if (p) { bp_free(p); free(p); }
    return result ? 2 : 0;
}
