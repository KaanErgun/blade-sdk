/* MIT License, copyright (c) 2026 Kaan Ergun. */
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include "package.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

static const char *error_message = "invalid package";
#define CHECK(c, m) do { if (!(c)) { error_message = (m); return -1; } } while (0)
const char *bp_error(void) { return error_message; }
static uint16_t u16(const unsigned char *p) { return p[0] | (uint16_t)p[1] << 8; }
static uint32_t u32(const unsigned char *p) { return u16(p) | (uint32_t)u16(p + 2) << 16; }
static uint64_t u64(const unsigned char *p) { return u32(p) | (uint64_t)u32(p + 4) << 32; }
static int digest(const void *data, size_t size, char out[65])
{
    unsigned char hash[32]; unsigned length = 0;
    CHECK(EVP_Digest(data, size, hash, &length, EVP_sha256(), NULL) == 1 && length == 32,
          "SHA256 failed");
    for (unsigned i = 0; i < 32; ++i) snprintf(out + i * 2, 3, "%02x", hash[i]);
    return 0;
}
static int hash_string(const char *value)
{
    if (strlen(value) != 64) return 0;
    for (unsigned i = 0; i < 64; ++i)
        if (!strchr("0123456789abcdef", value[i])) return 0;
    return 1;
}
int bp_id(const char *value)
{
    size_t n = strlen(value); int separator = 0, previous = 0;
    if (!n || n > 96) return 0;
    for (size_t i = 0; i < n; ++i) {
        int sep = value[i] == '.' || value[i] == '-';
        if (sep) { if (!i || previous || i + 1 == n) return 0; separator = 1; }
        else if (!((value[i] >= 'a' && value[i] <= 'z') || isdigit((unsigned char)value[i]))) return 0;
        previous = sep;
    }
    return separator;
}
static int safe_path(const char *value)
{
    size_t n = strlen(value), start = 0;
    if (!n || n > 240 || !(isalnum((unsigned char)value[0]) || value[0] == '_')) return 0;
    for (size_t i = 0; i <= n; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (c > 127 || (c && !isalnum(c) && !strchr("_./-", c))) return 0;
        if (!c || c == '/') {
            size_t length = i - start;
            if (!length || (length == 1 && value[start] == '.') ||
                (length == 2 && !strncmp(value + start, "..", 2))) return 0;
            start = i + 1;
        }
    }
    return 1;
}
int bp_version_valid(const char *value)
{
    const char *p = value;
    for (int i = 0; i < 3; ++i) {
        const char *begin = p;
        while (isdigit((unsigned char)*p)) ++p;
        if (p == begin || (p - begin > 1 && *begin == '0')) return 0;
        if (i < 2 && *p++ != '.') return 0;
    }
    if (*p == '-') {
        ++p;
        for (;;) {
            const char *begin = p; int numeric = 1;
            while (isalnum((unsigned char)*p) || *p == '-') { if (!isdigit((unsigned char)*p)) numeric = 0; ++p; }
            if (p == begin || (numeric && p - begin > 1 && *begin == '0')) return 0;
            if (*p != '.') break;
            ++p;
        }
    }
    if (*p == '+') {
        do {
            const char *begin = ++p;
            while (isalnum((unsigned char)*p) || *p == '-') ++p;
            if (p == begin) return 0;
        } while (*p == '.');
    }
    return !*p;
}
static int numeric_compare(const char *a, size_t na, const char *b, size_t nb)
{
    if (na != nb) return na < nb ? -1 : 1;
    int result = strncmp(a, b, na); return (result > 0) - (result < 0);
}
int bp_version_compare(const char *a, const char *b)
{
    for (unsigned i = 0; i < 3; ++i) {
        size_t na = strspn(a, "0123456789"), nb = strspn(b, "0123456789");
        int result = numeric_compare(a, na, b, nb); if (result) return result;
        a += na; b += nb; if (i < 2) { ++a; ++b; }
    }
    if (*a != '-' || *b != '-') return (*b == '-') - (*a == '-');
    ++a; ++b;
    for (;;) {
        size_t na = strcspn(a, ".+"), nb = strcspn(b, ".+");
        int an = strspn(a, "0123456789") == na, bn = strspn(b, "0123456789") == nb;
        int result;
        if (an && bn) result = numeric_compare(a, na, b, nb);
        else if (an != bn) result = an ? -1 : 1;
        else { size_t n = na < nb ? na : nb; result = strncmp(a, b, n); if (!result) result = (na > nb) - (na < nb); }
        if (result) return result > 0 ? 1 : -1;
        a += na; b += nb;
        if (*a != '.' || *b != '.') return (*a == '.') - (*b == '.');
        ++a; ++b;
    }
}

struct json { const unsigned char *p, *end; };
static int take(struct json *j, const char *literal)
{
    size_t n = strlen(literal);
    CHECK((size_t)(j->end - j->p) >= n && !memcmp(j->p, literal, n), "noncanonical JSON or unexpected field");
    j->p += n; return 0;
}
static int hex4(struct json *j, unsigned *value)
{
    CHECK(j->end - j->p >= 4, "truncated Unicode escape"); *value = 0;
    for (unsigned i = 0; i < 4; ++i) {
        const char *digit = strchr("0123456789abcdef", *j->p++);
        CHECK(digit && digit != strchr("0123456789abcdef", 0), "noncanonical Unicode escape");
        *value = *value * 16 + (unsigned)(digit - "0123456789abcdef");
    }
    return 0;
}
static int string(struct json *j, char *out, size_t capacity, size_t maximum)
{
    size_t n = 0, characters = 0;
    if (take(j, "\"") < 0) return -1;
    while (j->p < j->end && *j->p != '"') {
        unsigned c = *j->p++;
        CHECK(c >= 32 && c < 127, "JSON must use canonical ASCII escapes");
        if (c == '\\') {
            CHECK(j->p < j->end, "truncated escape"); c = *j->p++;
            if (c == 'u') {
                if (hex4(j, &c) < 0) return -1;
                CHECK(c >= 127 && !(c >= 0xdc00 && c <= 0xdfff), "invalid or unnecessary Unicode escape");
                if (c >= 0xd800 && c <= 0xdbff) {
                    unsigned low;
                    if (take(j, "\\u") < 0 || hex4(j, &low) < 0) return -1;
                    CHECK(low >= 0xdc00 && low <= 0xdfff, "unpaired surrogate");
                    c = 0x10000 + ((c - 0xd800) << 10) + low - 0xdc00;
                }
            } else CHECK(c == '\\' || c == '"', "control character or noncanonical escape");
        }
        CHECK(c != 127 && ++characters <= maximum, "invalid text length or control character");
        unsigned char encoded[4]; unsigned bytes;
        if (c < 128) { encoded[0] = (unsigned char)c; bytes = 1; }
        else if (c < 2048) { encoded[0] = 0xc0 | (c >> 6); encoded[1] = 0x80 | (c & 63); bytes = 2; }
        else if (c < 65536) { encoded[0] = 0xe0 | (c >> 12); encoded[1] = 0x80 | ((c >> 6) & 63); encoded[2] = 0x80 | (c & 63); bytes = 3; }
        else { encoded[0] = 0xf0 | (c >> 18); encoded[1] = 0x80 | ((c >> 12) & 63); encoded[2] = 0x80 | ((c >> 6) & 63); encoded[3] = 0x80 | (c & 63); bytes = 4; }
        CHECK(n + bytes < capacity, "text buffer limit"); memcpy(out + n, encoded, bytes); n += bytes;
    }
    CHECK(characters > 0, "empty text"); out[n] = 0; return take(j, "\"");
}
static int number(struct json *j, uint32_t *value)
{
    const unsigned char *begin = j->p; uint64_t n = 0;
    while (j->p < j->end && *j->p >= '0' && *j->p <= '9') {
        n = n * 10 + *j->p++ - '0'; CHECK(n <= UINT32_MAX, "integer overflow");
    }
    CHECK(j->p > begin && (j->p - begin == 1 || *begin != '0'), "noncanonical integer");
    *value = (uint32_t)n; return 0;
}
static int parse_manifest(struct bp_package *p)
{
    struct json j = { p->manifest, p->manifest + p->manifest_size };
    char text[8193]; uint32_t n; uint64_t total = 0;
#define T(v) do { if (take(&j, v) < 0) return -1; } while (0)
#define S(v, max) do { if (string(&j, v, sizeof(v), max) < 0) return -1; } while (0)
    T("{\"entrypoint\":"); S(p->entrypoint, 240); CHECK(safe_path(p->entrypoint), "unsafe entrypoint");
    T(",\"entrypoint_type\":"); S(text, 6); CHECK(!strcmp(text, "script") || !strcmp(text, "elf"), "invalid entrypoint type"); p->elf = !strcmp(text, "elf");
    T(",\"files\":{");
    do {
        CHECK(p->count < BP_MAX_FILES, "file count limit"); struct bp_file *f = &p->files[p->count];
        S(f->path, 240); CHECK(safe_path(f->path), "unsafe payload path");
        if (p->count) CHECK(strcmp(p->files[p->count - 1].path, f->path) < 0, "unordered or duplicate file key");
        T(":{\"bytes\":"); if (number(&j, &f->size) < 0) return -1;
        T(",\"mode\":"); if (number(&j, &f->mode) < 0) return -1;
        T(",\"sha256\":"); S(f->hash, 64); T("}");
        CHECK(f->size <= BP_MAX_FILE && (f->mode == 0444 || f->mode == 0555) && hash_string(f->hash), "invalid file metadata");
        total += f->size; CHECK(total <= BP_MAX_PAYLOAD, "expanded payload limit");
        ++p->count;
        CHECK(j.p < j.end, "truncated files"); if (*j.p != ',') break; ++j.p;
    } while (1);
    T("},\"id\":"); S(p->id, 96); CHECK(bp_id(p->id), "invalid application id");
    T(",\"kind\":\"blade-app\",\"license\":"); S(text, 128);
    T(",\"name\":"); S(text, 96);
    T(",\"permissions\":[");
    while (j.p < j.end && *j.p != ']') {
        static const char *names[] = { "camera", "microphone", "hud", "network", "storage", "root" };
        S(text, 10); unsigned bit = 0;
        for (unsigned i = 0; i < 6; ++i) if (!strcmp(text, names[i])) bit = 1u << i;
        CHECK(bit && !(p->permissions & bit), "unknown or duplicate permission"); p->permissions |= bit;
        CHECK(j.p < j.end, "truncated permissions"); if (*j.p != ',') break; ++j.p;
        CHECK(j.p < j.end && *j.p != ']', "trailing array comma");
    }
    T("],\"run_as\":"); S(text, 4); CHECK(!strcmp(text, "app") || !strcmp(text, "root"), "invalid run_as"); p->root = !strcmp(text, "root");
    CHECK(!!(p->permissions & BP_ROOT) == p->root, "root permission mismatch");
    T(",\"schema_version\":"); if (number(&j, &n) < 0) return -1; CHECK(n == 1, "unsupported schema");
    T(",\"signer\":"); S(p->signer, 64); CHECK(hash_string(p->signer), "invalid signer");
    T(",\"source\":"); S(text, 2048);
    const char *host = !strncmp(text, "https://", 8) ? text + 8 : !strncmp(text, "http://", 7) ? text + 7 : NULL;
    CHECK(host && *host && *host != '/' && !strpbrk(host, "@?# \\"), "invalid source URL");
    T(",\"target\":\"linux-aarch64\",\"version\":"); S(p->version, 64); CHECK(bp_version_valid(p->version), "invalid SemVer");
    T("}\n"); CHECK(j.p == j.end, "trailing manifest data");
    int entry = 0;
    for (size_t i = 0; i < p->count; ++i) {
        const char *a = p->files[i].path;
        if (!strcmp(a, p->entrypoint)) entry = p->files[i].mode == 0555;
        for (size_t k = 0; k < i; ++k) {
            const char *b = p->files[k].path; size_t na = strlen(a), nb = strlen(b), small = na < nb ? na : nb;
            CHECK(strncasecmp(a, b, small) || (na != nb && (na < nb ? b[small] : a[small]) != '/'), "case collision or file/directory conflict");
        }
    }
    CHECK(entry, "missing executable entrypoint"); return 0;
#undef T
#undef S
}

struct zip_entry { char name[249]; uint32_t size, compressed, crc, offset, mode, start, end; uint16_t method; };
static int zip_data(const unsigned char *raw, const struct zip_entry *entry, unsigned char **out)
{
    unsigned char *data = malloc((size_t)entry->size + 1); CHECK(data, "out of memory");
    if (!entry->method) {
        if (entry->compressed != entry->size) { free(data); CHECK(0, "stored ZIP size mismatch"); }
        memcpy(data, raw + entry->start, entry->size);
    } else {
        z_stream stream = {0}; stream.next_in = (Bytef *)raw + entry->start; stream.avail_in = entry->compressed;
        stream.next_out = data; stream.avail_out = entry->size + 1;
        int initialized = inflateInit2(&stream, -MAX_WBITS);
        int result = initialized == Z_OK ? inflate(&stream, Z_FINISH) : initialized;
        int valid = result == Z_STREAM_END && stream.total_out == entry->size && stream.total_in == entry->compressed;
        if (initialized == Z_OK) inflateEnd(&stream);
        if (!valid) { free(data); CHECK(0, "invalid or oversized deflate stream"); }
    }
    if ((uint32_t)crc32(0, data, entry->size) != entry->crc) { free(data); CHECK(0, "ZIP CRC mismatch"); }
    data[entry->size] = 0; *out = data; return 0;
}
static int entrypoint(const struct bp_package *p, const struct bp_file *f)
{
    const unsigned char *d = f->data; size_t n = f->size;
    if (!p->elf) {
        CHECK(n >= 10 && !memcmp(d, "#!/bin/sh\n", 10) && !memchr(d, 0, n), "invalid script entrypoint");
        /* Validate UTF-8, including overlong forms and surrogate encodings. */
        for (size_t i = 0; i < n;) {
            unsigned c = d[i++], continuation = 0, minimum = 0;
            if (c < 128) continue;
            if (c >= 0xc2 && c <= 0xdf) { continuation = 1; minimum = 128; c &= 31; }
            else if (c >= 0xe0 && c <= 0xef) { continuation = 2; minimum = 2048; c &= 15; }
            else if (c >= 0xf0 && c <= 0xf4) { continuation = 3; minimum = 65536; c &= 7; }
            else CHECK(0, "invalid UTF-8 script");
            CHECK(n - i >= continuation, "truncated UTF-8 script");
            while (continuation--) { CHECK((d[i] & 0xc0) == 0x80, "invalid UTF-8 script"); c = (c << 6) | (d[i++] & 63); }
            CHECK(c >= minimum && c <= 0x10ffff && !(c >= 0xd800 && c <= 0xdfff), "invalid UTF-8 script");
        }
        return 0;
    }
    CHECK(n >= 64 && !memcmp(d, "\177ELF\2\1\1", 7) && (u16(d + 16) == 2 || u16(d + 16) == 3) &&
          u16(d + 18) == 183 && u32(d + 20) == 1 && u16(d + 52) == 64 && u16(d + 54) == 56, "invalid AArch64 ELF");
    uint64_t start = u64(d + 32), address = u64(d + 24); unsigned count = u16(d + 56); int executable = 0;
    CHECK(count && count <= 128 && start >= 64 && start <= n && count * 56 <= n - start, "invalid ELF program headers");
    for (unsigned i = 0; i < count; ++i) {
        const unsigned char *h = d + start + i * 56; uint64_t offset = u64(h + 8), base = u64(h + 16), size = u64(h + 32), memory = u64(h + 40);
        CHECK(offset <= n && size <= n - offset, "ELF segment outside file");
        if (u32(h) == 1) { CHECK(size <= memory, "invalid ELF memory size"); if ((u32(h + 4) & 1) && address >= base && address - base < memory) executable = 1; }
    }
    CHECK(executable, "ELF entrypoint outside executable segment"); return 0;
}
static int decode(const unsigned char *raw, size_t bytes, struct bp_package *p)
{
    struct zip_entry entries[BP_MAX_FILES + 2] = {0};
    CHECK(bytes >= 22 && u32(raw) == 0x04034b50, "only ZIP packages are supported");
    const unsigned char *end = raw + bytes - 22;
    unsigned count = u16(end + 10); size_t directory = u32(end + 16), length = u32(end + 12);
    CHECK(u32(end) == 0x06054b50 && !u16(end + 4) && !u16(end + 6) && !u16(end + 20) &&
          count == u16(end + 8) && count > 2 && count <= BP_MAX_FILES + 2 && length <= (BP_MAX_FILES + 2) * 512 &&
          directory <= bytes - 22 && length == bytes - 22 - directory, "invalid ZIP directory or limits");
    size_t position = directory; int manifest = -1, signature = -1;
    for (unsigned i = 0; i < count; ++i) {
        struct zip_entry *e = &entries[i]; CHECK(position + 46 <= bytes - 22, "truncated ZIP directory");
        const unsigned char *h = raw + position; unsigned name = u16(h + 28);
        CHECK(u32(h) == 0x02014b50 && (u16(h + 4) >> 8) == 3 && u16(h + 6) <= 20 && !u16(h + 8) &&
              !u16(h + 30) && !u16(h + 32) && !u16(h + 34) && name && name < sizeof(e->name) && position + 46 + name <= bytes - 22,
              "unsupported ZIP attributes");
        memcpy(e->name, h + 46, name); CHECK(strlen(e->name) == name, "NUL ZIP path");
        e->method = u16(h + 10); e->crc = u32(h + 16); e->compressed = u32(h + 20); e->size = u32(h + 24);
        e->mode = u32(h + 38) >> 16; e->offset = u32(h + 42);
        CHECK((e->mode == (0100000 | 0444) || e->mode == (0100000 | 0555)) && (e->method == 0 || e->method == 8), "unsafe ZIP mode or compression");
        for (unsigned k = 0; k < i; ++k) CHECK(strcasecmp(e->name, entries[k].name), "duplicate ZIP path");
        if (!strcmp(e->name, "manifest.json")) { CHECK(e->size <= BP_MAX_METADATA, "manifest size limit"); manifest = (int)i; }
        else if (!strcmp(e->name, "signature.ed25519")) { CHECK(e->size == 64, "signature size"); signature = (int)i; }
        else CHECK(!strncmp(e->name, "payload/", 8) && safe_path(e->name + 8) && e->size <= BP_MAX_FILE, "unsafe ZIP payload");
        CHECK((uint64_t)e->offset + 30 + name <= directory, "local ZIP offset outside data");
        const unsigned char *local = raw + e->offset;
        CHECK(u32(local) == 0x04034b50 && u16(local + 4) <= 20 && !u16(local + 6) && u16(local + 8) == e->method &&
              u32(local + 14) == e->crc && u32(local + 18) == e->compressed && u32(local + 22) == e->size &&
              u16(local + 26) == name && !u16(local + 28) && !memcmp(local + 30, e->name, name), "ZIP local/central disagreement");
        e->start = e->offset + 30 + name;
        CHECK(e->compressed <= directory - e->start, "ZIP compressed data exceeds bound"); e->end = e->start + e->compressed;
        position += 46 + name;
    }
    CHECK(position == bytes - 22 && manifest >= 0 && signature >= 0, "missing metadata or trailing ZIP directory");
    position = 0;
    for (unsigned i = 0; i < count; ++i) {
        int found = 0;
        for (unsigned k = 0; k < count; ++k) if (entries[k].offset == position) { position = entries[k].end; found = 1; break; }
        CHECK(found, "overlapping or hidden ZIP data");
    }
    CHECK(position == directory, "unaccounted ZIP data");
    p->manifest_size = entries[manifest].size;
    if (zip_data(raw, &entries[manifest], &p->manifest) < 0 || parse_manifest(p) < 0) return -1;
    unsigned char *sig = NULL; if (zip_data(raw, &entries[signature], &sig) < 0) return -1;
    memcpy(p->signature, sig, 64); free(sig);
    CHECK(p->count + 2 == count, "archive/manifest file sets differ");
    for (size_t i = 0; i < p->count; ++i) {
        struct bp_file *f = &p->files[i]; int found = 0;
        for (unsigned k = 0; k < count; ++k) {
            struct zip_entry *e = &entries[k];
            if (strncmp(e->name, "payload/", 8) || strcmp(e->name + 8, f->path)) continue;
            CHECK(e->size == f->size && (e->mode & 07777) == f->mode, "manifest/ZIP size or mode mismatch");
            if (zip_data(raw, e, &f->data) < 0) return -1;
            char hash[65]; if (digest(f->data, f->size, hash) < 0) return -1;
            CHECK(!strcmp(hash, f->hash), "payload SHA256 mismatch"); found = 1; break;
        }
        CHECK(found, "manifest payload missing");
        if (!strcmp(f->path, p->entrypoint) && entrypoint(p, f) < 0) return -1;
    }
    return 0;
}
int bp_read(int fd, struct bp_package *p)
{
    struct stat before, after; memset(p, 0, sizeof(*p));
    CHECK(fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_size >= 22 && before.st_size <= BP_MAX_PACKAGE,
          "package input must be a bounded regular file");
    p->bytes = (size_t)before.st_size; unsigned char *raw = malloc(p->bytes); CHECK(raw, "out of memory");
    size_t done = 0;
    while (done < p->bytes) {
        ssize_t n = pread(fd, raw + done, p->bytes - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(raw); CHECK(0, "package read failed"); } done += (size_t)n;
    }
    int result = digest(raw, p->bytes, p->hash);
    if (!result) result = decode(raw, p->bytes, p);
    free(raw);
    if (fstat(fd, &after) < 0 || before.st_size != after.st_size || before.st_mtime != after.st_mtime || before.st_ctime != after.st_ctime) {
        error_message = "package changed while reading"; result = -1;
    }
    if (result) bp_free(p);
    return result;
}
int bp_verify(struct bp_package *p, const unsigned char *der, size_t bytes, int allow_root)
{
    static const unsigned char prefix[] = {0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0};
    CHECK(bytes == 44 && !memcmp(der, prefix, sizeof(prefix)), "trusted key must be Ed25519 SPKI DER");
    char hash[65]; if (digest(der, bytes, hash) < 0) return -1;
    CHECK(!strcmp(hash, p->signer), "package signer is not trusted");
    CHECK(!p->root || allow_root, "root package requires explicit owner opt-in");
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, der + 12, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int valid = key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(ctx, p->signature, 64, p->manifest, p->manifest_size) == 1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); CHECK(valid, "invalid Ed25519 signature"); p->verified = 1; return 0;
}
static int write_all(int fd, const unsigned char *p, size_t size)
{
    while (size) { ssize_t n = write(fd, p, size); if (n < 0 && errno == EINTR) continue; CHECK(n > 0, "payload write failed"); p += n; size -= (size_t)n; }
    return 0;
}
int bp_extract(const struct bp_package *p, int directory)
{
    CHECK(p->verified, "extraction requires verified signature");
    DIR *empty = fdopendir(dup(directory)); CHECK(empty, "open extraction directory");
    struct dirent *item; int clean = 1;
    while ((item = readdir(empty))) if (strcmp(item->d_name, ".") && strcmp(item->d_name, "..")) clean = 0;
    closedir(empty); CHECK(clean, "extraction directory must be empty");
    for (size_t i = 0; i < p->count; ++i) {
        const struct bp_file *f = &p->files[i]; char path[241]; strcpy(path, f->path);
        int parent = dup(directory); CHECK(parent >= 0, "directory dup failed");
        char *part = path, *slash;
        while ((slash = strchr(part, '/'))) {
            *slash = 0;
            if (mkdirat(parent, part, 0755) < 0 && errno != EEXIST) { close(parent); CHECK(0, "payload directory create failed"); }
            if (fsync(parent) < 0) { close(parent); CHECK(0, "payload directory flush failed"); }
            int child = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            close(parent); CHECK(child >= 0, "unsafe payload directory"); parent = child; part = slash + 1;
            if (fchmod(parent, 0755) < 0) { close(parent); CHECK(0, "payload directory mode failed"); }
        }
        int fd = openat(parent, part, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, f->mode);
        if (fd < 0) { close(parent); CHECK(0, "payload create failed"); }
        int result = write_all(fd, f->data, f->size);
        if (!result && (fchmod(fd, f->mode) < 0 || fsync(fd) < 0)) result = -1;
        if (close(fd) < 0) result = -1;
        if (fsync(parent) < 0) result = -1;
        close(parent); CHECK(!result, "payload flush failed");
    }
    CHECK(!fsync(directory), "payload directory flush failed"); return 0;
}
static int check_directory(const struct bp_package *p, int fd, const char *prefix, size_t *count)
{
    DIR *dir = fdopendir(dup(fd)); CHECK(dir, "open payload directory");
    struct dirent *item; int result = 0;
    while ((item = readdir(dir))) {
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        char path[241]; int n = snprintf(path, sizeof(path), "%s%s%s", prefix, *prefix ? "/" : "", item->d_name);
        if (n < 0 || (size_t)n >= sizeof(path) || !safe_path(path)) { error_message = "unsafe installed path"; result = -1; break; }
        struct stat st;
        if (fstatat(fd, item->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0 || st.st_uid != geteuid()) { error_message = "installed file owner changed"; result = -1; break; }
        if (S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0755) {
            int child = openat(fd, item->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) { result = -1; break; }
            result = check_directory(p, child, path, count); close(child); if (result) break;
            continue;
        }
        const struct bp_file *f = NULL;
        for (size_t i = 0; i < p->count; ++i) if (!strcmp(p->files[i].path, path)) { f = &p->files[i]; break; }
        if (!f || !S_ISREG(st.st_mode) || (st.st_mode & 07777) != f->mode || st.st_size != f->size) { error_message = "installed file set, mode or size changed"; result = -1; break; }
        int source = openat(fd, item->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); if (source < 0) { result = -1; break; }
        size_t done = 0; unsigned char buffer[65536];
        while (done < f->size) {
            size_t length = f->size - done; if (length > sizeof(buffer)) length = sizeof(buffer);
            ssize_t got = read(source, buffer, length); if (got < 0 && errno == EINTR) continue;
            if (got <= 0 || memcmp(buffer, f->data + done, (size_t)got)) { error_message = "installed payload content changed"; result = -1; break; }
            done += (size_t)got;
        }
        close(source); if (result) break; ++*count;
    }
    closedir(dir); return result;
}
int bp_check_tree(const struct bp_package *p, int directory)
{
    CHECK(p->verified, "installed tree requires verified signature"); size_t count = 0;
    if (check_directory(p, directory, "", &count) < 0) return -1;
    CHECK(count == p->count, "installed payload missing"); return 0;
}
void bp_free(struct bp_package *p)
{
    free(p->manifest); p->manifest = NULL;
    for (size_t i = 0; i < p->count; ++i) { free(p->files[i].data); p->files[i].data = NULL; }
    p->verified = 0;
}
