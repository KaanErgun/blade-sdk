/* MIT License, copyright (c) 2026 Kaan Ergun. */
#ifndef BLADE_PACKAGE_H
#define BLADE_PACKAGE_H
#include <stddef.h>
#include <stdint.h>

#define BP_MAX_FILES 512
#define BP_MAX_PACKAGE (64u * 1024u * 1024u)
#define BP_MAX_PAYLOAD (32u * 1024u * 1024u)
#define BP_MAX_FILE (16u * 1024u * 1024u)
#define BP_MAX_METADATA (128u * 1024u)
#define BP_CAMERA 1u
#define BP_MICROPHONE 2u
#define BP_HUD 4u
#define BP_NETWORK 8u
#define BP_STORAGE 16u
#define BP_ROOT 32u

struct bp_file {
    char path[241], hash[65];
    uint32_t size, mode;
    unsigned char *data;
};
struct bp_package {
    char id[97], version[65], entrypoint[241], signer[65], hash[65];
    unsigned permissions;
    int root, elf, verified;
    size_t count, bytes, manifest_size;
    unsigned char *manifest, signature[64];
    struct bp_file files[BP_MAX_FILES];
};

/* Input is a regular file opened by the caller; all bytes are copied and bounded. */
int bp_read(int fd, struct bp_package *package);
/* A trusted Ed25519 SPKI DER is exactly 44 bytes; no package-provided key is used. */
int bp_verify(struct bp_package *package, const unsigned char *der, size_t bytes,
              int allow_root);
/* Extract only verified bytes into an empty caller-owned directory descriptor. */
int bp_extract(const struct bp_package *package, int directory);
int bp_check_tree(const struct bp_package *package, int directory);
void bp_free(struct bp_package *package);
const char *bp_error(void);
int bp_id(const char *id);
int bp_version_valid(const char *version);
/* SemVer precedence; equal build-metadata variants compare equal. */
int bp_version_compare(const char *a, const char *b);
#endif
