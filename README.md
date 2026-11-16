# Blade SDK

Unofficial · by Kaan Ergün

A small application packaging SDK for the independent Blade Linux project. It creates and verifies signed `.bladeapp` packages and static application catalogs. Its Python API does not extract or execute packages. The native C library verifies the same package format and extracts verified bytes into a caller-owned staging directory; the OS owns install, update, isolation, launch and removal. The [v1 application and owner protocols](docs/device-v1.md) document the implemented text-HUD boundary and separate camera/management transport; packaging does not grant those owner credentials. This project is independent of Vuzix.

SDK version: `0.1.0-dev`. Package and catalog format version: `1`. Product release acceptance and device support are separate from this packaging tool. Living implementation status is in [docs/durum.md](docs/durum.md).

## Requirements and local check

- Python 3.10 or later, standard library only.
- OpenSSL 3 CLI with Ed25519 support, available as `openssl` or selected with `OPENSSL=/absolute/path/to/openssl`.
- A C11 compiler, pkg-config, OpenSSL 3 libcrypto development files and zlib development files for native checks.
- A local filesystem supporting atomic hard-link creation in the output directory. Outputs never replace existing files.

```sh
./scripts/check.sh
```

The gate compiles native C and Python source and runs contract, SemVer, cross-language archive and real CLI tests with temporary keys. No network, device, hosted CI, or application execution is used.

## Create and verify an application

From a clean checkout:

```sh
mkdir -p .keys build
python3 blade_sdk.py keygen --private .keys/publisher.pem --public .keys/publisher-public.pem
python3 blade_sdk.py pack \
  --manifest examples/hello/app.json \
  --payload examples/hello/payload \
  --key .keys/publisher.pem \
  --output build/hello.bladeapp
python3 blade_sdk.py verify build/hello.bladeapp --key .keys/publisher-public.pem
```

Private keys are unencrypted local PEM files with mode `0600`; keep them outside source control. Encrypted key/passphrase workflows are not implemented. Existing keys and outputs are preserved. Run commands with new output paths when producing another artifact.

The hello example requests `hud` and prints its Turkish resource file from
`payload/text/tr.txt`. After the owner trusts its publisher and explicitly grants
HUD permission at installation, open it from the glasses' **Uygulamalar** menu.
Blade OS retains the text after the script exits; two-finger Back returns to the
list. This interface is plain stdout, limited to 512 displayed UTF-8 bytes and
4096 emitted bytes per session; it grants no framebuffer, input, camera or
microphone access. The phone installs/manages HUD apps but does not launch them.

`app.json` contains `id`, `version`, `name`, `entrypoint`, `entrypoint_type`, `license`, and `source`. The `permissions` list defaults to empty and `run_as` defaults to `app`. `source` is an HTTP(S) source-code URL, not a download request made by this tool. Unknown fields and duplicate JSON keys are rejected.

Entrypoints are either:

- `script`: UTF-8, no NUL bytes, beginning with exactly `#!/bin/sh` and an LF newline. The example prints a greeting when an OS launcher explicitly runs it.
- `elf`: a little-endian AArch64 ELF64 executable with bounded program headers and an entrypoint inside an executable load segment. This is a format check, not proof that the binary's libraries or device interfaces are available.

Other executable architectures, symlinks, special files, unsafe relative paths, and conflicting paths are rejected. The tool records the entrypoint as mode `0555`; other payload files use `0444` or `0555`. It never preserves setuid or writable executable modes.

## Trust and root applications

Verification requires a public key supplied by the caller. An archive cannot establish its own trust. The manifest's `signer` is the SHA256 of the Ed25519 public key's SubjectPublicKeyInfo DER; the signature covers the complete canonical manifest, including every payload SHA256, size, and mode. Payload files are then checked against that manifest.

Permissions are declarations: `camera`, `microphone`, `hud`, `network`, `storage`, and `root`. This SDK does not grant or enforce device permissions. Normal packages use `run_as: "app"`. A device-owner root package must declare both `run_as: "root"` and the `root` permission; packing and verification each additionally require `--allow-root`. A publisher signature alone never opts into root execution. The OS installer must obtain the device owner's authorization and enforce the declared privilege boundary. Native verification also requires explicit root opt-in; it never changes process privileges.

## Package format and limits

Only ZIP `.bladeapp` is supported. TAR, gzip TAR, ZIP64, split archives, archive comments, extra fields, encrypted entries, and compression methods other than stored/deflate are rejected.

```text
manifest.json
signature.ed25519
payload/bin/hello
payload/...
```

There are no explicit directory entries. Paths use portable ASCII POSIX names; absolute paths, backslashes, empty/`.`/`..` components, NULs, case collisions, file/directory conflicts, and duplicate entries are rejected. Every archive payload file must appear exactly once in the signed manifest; extra files are rejected.

| Limit | Value |
|---|---|
| Complete package | 64 MiB |
| Expanded payload total | 32 MiB |
| Individual payload file | 16 MiB |
| Payload file count | 512 |
| Manifest or signed catalog | 128 KiB |
| Relative payload path | 240 characters |
| Ed25519 signature | 64 bytes |

The verifier bounds the central directory before constructing ZIP entry objects, checks declared sizes before decompression, and reads payloads in bounded chunks. Package generation stages a complete output before publishing it without replacement. A failed operation removes its temporary output, not an existing package.

Canonical JSON is ASCII `json.dumps` with sorted keys, compact separators, `ensure_ascii=True`, no non-finite numbers, and one final LF. The manifest must use these exact bytes. The Ed25519 signature is stored as 64 raw bytes. ZIP metadata is deterministic within the same Python/zlib toolchain; exact bytes across different compression implementations are not promised.

[Manifest schema](schemas/manifest-v1.schema.json) and [catalog schema](schemas/catalog-v1.schema.json) describe the wire structure. Schema validation alone does not verify an archive, signature, entrypoint, or aggregate limits; use the CLI or Python API.

## Create and verify a static catalog

```sh
python3 blade_sdk.py catalog build/hello.bladeapp \
  --key .keys/publisher.pem \
  --base-url https://example.invalid/blade/apps \
  --revision 1 --output build/catalog.json
python3 blade_sdk.py verify-catalog build/catalog.json --key .keys/publisher-public.pem
```

The example URL is a placeholder. No hosting or network request is created. The command verifies each package first, then signs a catalog containing its id/version, URL, complete package hash/size, publisher fingerprint, privilege level, and permissions. By default packages use the catalog publisher's key; repeat `--package-key trusted-public.pem` for independent trusted application publishers. Root packages require `--allow-root` for catalog creation and verification as well.

The catalog envelope contains `catalog` and a base64 `signature` over the canonical `catalog` object. Each catalog has one selected version per app id and a positive `revision`. The catalog consumer must remember trusted revisions, reject unauthorized rollback, verify the downloaded package hash, and independently verify its publisher signature before installation. Catalog verification does not fetch or install packages, make application signatures trusted automatically, or implement persistent rollback policy. The Android companion consumes this exact format using an explicitly selected catalog key, persists a revision high-water mark per key, and checks signed download size/hash before the separate OS package preview and owner confirmation. It requires platform Ed25519 support for catalog operations; older providers fail closed without an extra cryptography dependency. The application publisher must still be trusted independently on Blade.

## Reuse from an OS installer

```python
from blade_sdk import PackageError, verify

verified = verify("hello.bladeapp", "trusted-publisher.pem")
manifest = verified["manifest"]
package_hash = verified["package_sha256"]
```

Treat the verified hash as the identity of the input bytes. Keep the package immutable or recheck it immediately before consuming it; the SDK does not install files after verification. Blade OS implements the lifecycle separately, using this repository's native verifier. Catalog revision persistence and remote management authorization remain responsibilities of the consumer. The [device v1 contract](docs/device-v1.md) and shared golden fixture define the implemented OS camera/HUD and app-management wire protocol. JVM/Swift library bindings and a hosted market server are not provided by this SDK.

## Native OS integration

`native/package.h` exposes `bp_read`, `bp_verify`, `bp_extract`, `bp_check_tree`,
SemVer precedence and cleanup. `bp_read` copies a bounded regular-file descriptor,
checks the ZIP/manifest contract and payload bytes; `bp_verify` then requires an
externally trusted, exactly 44-byte Ed25519 SubjectPublicKeyInfo DER and explicit
root opt-in. Extraction is forbidden before verification and requires an empty
staging directory. It uses directory descriptors, no-follow opens, exclusive file
creation, fixed read-only modes and fsync. `bp_check_tree` detects installed byte,
file-set, ownership and mode changes before launch.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror $(pkg-config --cflags openssl zlib) \
  native/package.c native/verify.c $(pkg-config --libs openssl zlib) -o blade-verify
openssl pkey -pubin -in publisher-public.pem -outform DER -out publisher.der
./blade-verify hello.bladeapp publisher.der
```

The native reader accepts the SDK's canonical stored/deflate packages, requires
matching local/central ZIP headers and contiguous accounted archive data, and
rejects unsupported ZIP flags. Package format version remains `1`. The native
library does not pick trust keys, map owner permissions, create UIDs, mount a
sandbox or execute a program. No phone-provided verification result can replace
its signature verification. The OS adapter owns those decisions.

## License

MIT, copyright © 2026 Kaan Ergün. See [LICENSE](LICENSE). This repository contains no vendor firmware or decompiled vendor application code.
