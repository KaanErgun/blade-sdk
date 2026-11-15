#!/usr/bin/env python3
"""Signed Blade application packages. This module never extracts or runs apps."""

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlsplit
import zipfile
import zlib

VERSION = "0.1.0-dev"
FORMAT_VERSION = 1
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILES = 512
MAX_METADATA_BYTES = 128 * 1024
CHUNK_BYTES = 64 * 1024
PERMISSIONS = frozenset({"camera", "microphone", "hud", "network", "storage", "root"})
ID_PATTERN = r"[a-z0-9]+(?:[.-][a-z0-9]+)+"
PATH_PATTERN = r"[A-Za-z0-9_][A-Za-z0-9_./-]*"
HASH_PATTERN = r"[0-9a-f]{64}"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
SOURCE_FIELDS = {"id", "version", "name", "entrypoint", "entrypoint_type", "license", "source", "permissions", "run_as"}
MANIFEST_FIELDS = SOURCE_FIELDS | {"schema_version", "kind", "target", "signer", "files"}


class PackageError(ValueError):
    """Invalid or unsupported package, metadata, signature, or operation."""


def require(condition, message):
    if not condition:
        raise PackageError(message)


def canonical(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise PackageError("non-finite JSON value")


def parse_json(data, *, exact=False):
    require(len(data) <= MAX_METADATA_BYTES, "metadata exceeds size limit")
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                            parse_constant=_reject_constant)
        require(type(result) is dict, "metadata must be a JSON object")
        if exact:
            require(canonical(result) == data, "metadata is not canonical JSON")
        return result
    except PackageError:
        raise
    except (UnicodeError, ValueError, RecursionError, TypeError) as error:
        raise PackageError("invalid JSON metadata") from error


def read_metadata(path):
    with Path(path).open("rb") as source:
        return parse_json(source.read(MAX_METADATA_BYTES + 1))


def _text(value, name, maximum=128):
    require(type(value) is str and 0 < len(value) <= maximum, "invalid " + name)
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), "control character in " + name)


def _version(value):
    _text(value, "version", 64)
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?", value)
    require(match is not None, "version must be SemVer without a v prefix")
    for suffix in (match[4], match[5]):
        if suffix is not None:
            require(all(suffix.split(".")), "empty version identifier")
    if match[4]:
        require(all(not (part.isdigit() and len(part) > 1 and part[0] == "0")
                    for part in match[4].split(".")), "numeric prerelease has a leading zero")


def _url(value):
    _text(value, "URL", 2048)
    try:
        parts = urlsplit(value)
        require(parts.scheme in {"http", "https"} and parts.hostname is not None,
                "URL must be absolute HTTP(S)")
        require(parts.username is None and parts.password is None and not parts.fragment
                and not parts.query, "URL must not contain credentials, query, or fragment")
        _ = parts.port
    except ValueError as error:
        raise PackageError("invalid URL") from error


def safe_path(value):
    _text(value, "payload path", 240)
    require(re.fullmatch(PATH_PATTERN, value) is not None, "unsafe payload path")
    require(all(part not in {"", ".", ".."} for part in value.split("/")), "unsafe payload path segment")
    return value


def _permissions(value, run_as, allow_root):
    require(type(value) is list and all(type(item) is str for item in value), "permissions must be strings")
    require(len(value) == len(set(value)) and set(value) <= PERMISSIONS, "unknown or duplicate permission")
    require(type(run_as) is str and run_as in {"app", "root"}, "run_as must be app or root")
    require((run_as == "root") == ("root" in value), "root permission and run_as must agree")
    require(run_as != "root" or allow_root, "root package requires explicit --allow-root")


def validate_source(document, *, allow_root=False):
    require(type(document) is dict and set(document) == SOURCE_FIELDS, "unexpected or missing app metadata field")
    _text(document["id"], "id", 96)
    require(re.fullmatch(ID_PATTERN, document["id"]) is not None, "invalid application id")
    _version(document["version"])
    _text(document["name"], "name", 96)
    _text(document["license"], "license", 128)
    _url(document["source"])
    safe_path(document["entrypoint"])
    require(type(document["entrypoint_type"]) is str and document["entrypoint_type"] in {"script", "elf"}, "entrypoint_type must be script or elf")
    _permissions(document["permissions"], document["run_as"], allow_root)


def validate_manifest(document, *, allow_root=False):
    require(type(document) is dict and set(document) == MANIFEST_FIELDS, "unexpected or missing manifest field")
    require(type(document["schema_version"]) is int and document["schema_version"] == FORMAT_VERSION,
            "unsupported package format version")
    require(document["kind"] == "blade-app" and document["target"] == "linux-aarch64", "unsupported package target")
    require(type(document["signer"]) is str and re.fullmatch(HASH_PATTERN, document["signer"]), "invalid signer fingerprint")
    validate_source({key: document[key] for key in SOURCE_FIELDS}, allow_root=allow_root)
    files = document["files"]
    require(type(files) is dict and 0 < len(files) <= MAX_FILES, "invalid file count")
    total = 0
    folded = set()
    for path, metadata in files.items():
        safe_path(path)
        require(path.casefold() not in folded, "case-colliding payload paths")
        folded.add(path.casefold())
        require(type(metadata) is dict and set(metadata) == {"bytes", "sha256", "mode"}, "invalid file metadata")
        require(type(metadata["bytes"]) is int and 0 <= metadata["bytes"] <= MAX_FILE_BYTES, "file exceeds size limit")
        require(type(metadata["sha256"]) is str and re.fullmatch(HASH_PATTERN, metadata["sha256"]), "invalid file SHA256")
        require(type(metadata["mode"]) is int and metadata["mode"] in {0o444, 0o555}, "invalid file mode")
        total += metadata["bytes"]
    require(total <= MAX_PAYLOAD_BYTES, "payload exceeds size limit")
    require(document["entrypoint"] in files and files[document["entrypoint"]]["mode"] == 0o555,
            "entrypoint must be an executable payload file")
    # File/directory conflicts must be rejected before a future installer extracts.
    for path in files:
        parts = path.split("/")
        require(all("/".join(parts[:index]).casefold() not in folded for index in range(1, len(parts))),
                "payload file/directory conflict")


def _entrypoint(data, kind):
    if kind == "script":
        require(data.startswith(b"#!/bin/sh\n") and b"\0" not in data, "script must have an LF /bin/sh shebang and no NUL")
        try:
            data.decode("utf-8")
        except UnicodeError as error:
            raise PackageError("script must be UTF-8") from error
        return
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "entrypoint must be a little-endian ELF64")
    kind_id, machine, version, entry, phoff = struct.unpack_from("<HHIQQ", data, 16)
    ehsize, phsize, phcount = struct.unpack_from("<HHH", data, 52)
    require(kind_id in {2, 3} and machine == 183 and version == 1 and ehsize == 64,
            "entrypoint must be an AArch64 executable ELF")
    require(phsize == 56 and 0 < phcount <= 128 and phoff >= 64 and phoff + phsize * phcount <= len(data),
            "invalid ELF program headers")
    executable_entry = False
    for index in range(phcount):
        segment, flags, offset, address, _, size, memory, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phsize)
        require(offset + size <= len(data), "ELF segment outside file")
        if segment == 1:
            require(size <= memory, "ELF segment exceeds memory size")
            executable_entry |= bool(flags & 1 and address <= entry < address + memory)
    require(executable_entry, "ELF entrypoint is not in an executable load segment")


def _openssl(arguments):
    executable = os.environ.get("OPENSSL", "openssl")
    try:
        result = subprocess.run([executable, *arguments], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PackageError("OpenSSL 3 with Ed25519 support is required") from error
    require(result.returncode == 0, "OpenSSL key or signature operation failed")
    return result.stdout


def public_der(key, *, private=False):
    arguments = ["pkey", "-in", str(key)]
    arguments += ["-passin", "pass:"] if private else ["-pubin"]
    data = _openssl([*arguments, "-pubout", "-outform", "DER"])
    require(len(data) == 44 and data.startswith(ED25519_SPKI_PREFIX), "only Ed25519 keys are supported")
    return data


def fingerprint(key, *, private=False):
    return hashlib.sha256(public_der(key, private=private)).hexdigest()


def _signature(data, key, signature=None):
    with tempfile.TemporaryDirectory(prefix="blade-sign-") as temporary:
        message = Path(temporary) / "message"
        message.write_bytes(data)
        if signature is None:
            result = _openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-passin", "pass:", "-in", str(message)])
            require(len(result) == 64, "invalid Ed25519 signature length")
            return result
        require(len(signature) == 64, "invalid Ed25519 signature length")
        signature_path = Path(temporary) / "signature"
        signature_path.write_bytes(signature)
        _openssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(key),
                  "-in", str(message), "-sigfile", str(signature_path)])
        return None


def _publish(temporary, destination):
    # Linking publishes a complete file without replacing an existing output.
    os.link(temporary, destination)


def _atomic_bytes(destination, data, mode=0o644):
    destination = Path(destination)
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".blade-", delete=False) as target:
        temporary = Path(target.name)
        try:
            os.chmod(temporary, mode)
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
            _publish(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def keygen(private, public):
    private, public = Path(private), Path(public)
    require(not private.exists() and not public.exists() and private.absolute() != public.absolute(), "key output already exists or paths collide")
    with tempfile.TemporaryDirectory(prefix="blade-key-") as temporary:
        key = Path(temporary) / "private.pem"
        _openssl(["genpkey", "-algorithm", "ED25519", "-out", str(key)])
        pub = _openssl(["pkey", "-in", str(key), "-pubout"])
        _atomic_bytes(private, key.read_bytes(), 0o600)
        try:
            _atomic_bytes(public, pub)
        except Exception:
            private.unlink()
            raise
    return {"signer": fingerprint(public)}


def _source_files(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "payload must be a real directory")
    result = []
    for current, directories, files in os.walk(directory, followlinks=False):
        for name in directories:
            require(not (Path(current) / name).is_symlink(), "payload directory symlink is forbidden")
        for name in files:
            path = Path(current) / name
            require(stat.S_ISREG(path.lstat().st_mode), "payload contains a link or special file")
            relative = safe_path(path.relative_to(directory).as_posix())
            result.append((relative, path))
            require(len(result) <= MAX_FILES, "too many payload files")
    return sorted(result)


def _source_bytes(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES, "source file is invalid or too large")
        data = source.read(MAX_FILE_BYTES + 1)
        require(len(data) <= MAX_FILE_BYTES, "source file exceeds size limit")
        return data, info.st_mode


def _zip_write(archive, name, data, mode=0o444):
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, data, compresslevel=9)


def pack(metadata_path, payload_directory, output, key, *, allow_root=False):
    source = read_metadata(metadata_path)
    source.setdefault("run_as", "app")
    source.setdefault("permissions", [])
    validate_source(source, allow_root=allow_root)
    manifest = {**source, "schema_version": FORMAT_VERSION, "kind": "blade-app", "target": "linux-aarch64",
                "signer": fingerprint(key, private=True), "files": {}}
    output = Path(output)
    require(output.suffix == ".bladeapp", "package output must use .bladeapp")
    require(not output.exists(), "output already exists")
    require(not output.resolve().is_relative_to(Path(payload_directory).resolve()), "output must be outside payload directory")
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".blade-", delete=False) as target:
        temporary = Path(target.name)
    try:
        total = 0
        with zipfile.ZipFile(temporary, "w", allowZip64=False) as archive:
            for relative, path in _source_files(payload_directory):
                data, source_mode = _source_bytes(path)
                total += len(data)
                require(total <= MAX_PAYLOAD_BYTES, "payload exceeds size limit")
                mode = 0o555 if relative == source["entrypoint"] or source_mode & 0o111 else 0o444
                manifest["files"][relative] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "mode": mode}
                if relative == source["entrypoint"]:
                    _entrypoint(data, source["entrypoint_type"])
                _zip_write(archive, "payload/" + relative, data, mode)
            validate_manifest(manifest, allow_root=allow_root)
            data = canonical(manifest)
            require(len(data) <= MAX_METADATA_BYTES, "manifest exceeds size limit")
            _zip_write(archive, "manifest.json", data)
            _zip_write(archive, "signature.ed25519", _signature(data, key))
        require(temporary.stat().st_size <= MAX_PACKAGE_BYTES, "package exceeds size limit")
        with temporary.open("rb") as complete:
            os.fsync(complete.fileno())
        _publish(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"id": manifest["id"], "version": manifest["version"], "files": len(manifest["files"]), "bytes": output.stat().st_size}


def _hash_stream(source):
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(CHUNK_BYTES):
        size += len(chunk)
        require(size <= MAX_PACKAGE_BYTES, "package exceeds size limit")
        digest.update(chunk)
    return digest.hexdigest(), size


def _zip_directory_limit(source, size):
    # Reject oversized directories before ZipFile allocates one object per entry.
    require(size >= 22, "truncated ZIP package")
    source.seek(size - 22)
    magic, disk, directory_disk, on_disk, count, directory_bytes, offset, comment = struct.unpack("<4s4H2IH", source.read(22))
    require(magic == b"PK\x05\x06" and disk == directory_disk == comment == 0,
            "ZIP64, split ZIP, comments, and trailing data are unsupported")
    require(on_disk == count and 2 < count <= MAX_FILES + 2, "invalid archive entry count")
    require(directory_bytes <= (MAX_FILES + 2) * 512 and offset + directory_bytes == size - 22,
            "invalid or oversized ZIP central directory")
    source.seek(0)


def verify(path, key, *, allow_root=False):
    trusted = fingerprint(key)
    with Path(path).open("rb") as source:
        require(os.fstat(source.fileno()).st_size <= MAX_PACKAGE_BYTES, "package exceeds size limit")
        package_hash, package_size = _hash_stream(source)
        source.seek(0)
        require(source.read(4) == b"PK\x03\x04", "only ZIP .bladeapp packages are supported")
        _zip_directory_limit(source, package_size)
        try:
            with zipfile.ZipFile(source) as archive:
                entries = archive.infolist()
                require(2 < len(entries) <= MAX_FILES + 2, "invalid archive entry count")
                names, folded, payload_total = {}, set(), 0
                for entry in entries:
                    name = entry.filename
                    require(name not in names and name.casefold() not in folded, "duplicate or case-colliding archive entry")
                    names[name] = entry
                    folded.add(name.casefold())
                    require(entry.orig_filename == name and not entry.is_dir(), "directory or NUL archive entry is forbidden")
                    require(not entry.extra and not entry.comment, "ZIP extra fields and comments are unsupported")
                    mode = entry.external_attr >> 16
                    require(stat.S_ISREG(mode), "symlink or special archive entry is forbidden")
                    require(stat.S_IMODE(mode) in {0o444, 0o555}, "unsafe archive mode")
                    require(not entry.flag_bits & 1 and entry.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED},
                            "encrypted or unsupported ZIP compression")
                    if name == "manifest.json":
                        require(entry.file_size <= MAX_METADATA_BYTES, "manifest exceeds size limit")
                    elif name == "signature.ed25519":
                        require(entry.file_size == 64, "invalid signature size")
                    else:
                        require(name.startswith("payload/"), "unknown archive member")
                        safe_path(name[8:])
                        require(entry.file_size <= MAX_FILE_BYTES, "file exceeds size limit")
                        payload_total += entry.file_size
                        require(payload_total <= MAX_PAYLOAD_BYTES, "payload exceeds size limit")
                require("manifest.json" in names and "signature.ed25519" in names, "missing signed metadata")
                data = archive.read("manifest.json")
                manifest = parse_json(data, exact=True)
                validate_manifest(manifest, allow_root=allow_root)
                require(hmac.compare_digest(manifest["signer"], trusted), "package signer is not the trusted key")
                _signature(data, key, archive.read("signature.ed25519"))
                require(set(names) == {"manifest.json", "signature.ed25519"} | {"payload/" + name for name in manifest["files"]},
                        "archive and manifest file sets differ")
                for name, metadata in manifest["files"].items():
                    entry = names["payload/" + name]
                    require(entry.file_size == metadata["bytes"] and stat.S_IMODE(entry.external_attr >> 16) == metadata["mode"],
                            "payload size or mode differs from manifest")
                    digest, size, executable = hashlib.sha256(), 0, bytearray()
                    with archive.open(entry) as payload:
                        while chunk := payload.read(CHUNK_BYTES):
                            size += len(chunk)
                            require(size <= metadata["bytes"] and size <= MAX_FILE_BYTES, "expanded file exceeds limit")
                            digest.update(chunk)
                            if name == manifest["entrypoint"]:
                                executable.extend(chunk)
                    require(size == metadata["bytes"] and hmac.compare_digest(digest.hexdigest(), metadata["sha256"]),
                            "payload SHA256 or size mismatch")
                    if name == manifest["entrypoint"]:
                        _entrypoint(executable, manifest["entrypoint_type"])
        except (zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError, EOFError, OverflowError) as error:
            raise PackageError("invalid ZIP package") from error
        source.seek(0)
        require(_hash_stream(source) == (package_hash, package_size), "package changed during verification")
    return {"manifest": manifest, "package_sha256": package_hash, "package_bytes": package_size}


def _catalog(document, *, allow_root=False):
    require(type(document) is dict and set(document) == {"schema_version", "kind", "revision", "signer", "packages"}, "invalid catalog fields")
    require(type(document["schema_version"]) is int and document["schema_version"] == FORMAT_VERSION
            and document["kind"] == "blade-catalog", "unsupported catalog format")
    require(type(document["revision"]) is int and 1 <= document["revision"] <= 2**53 - 1, "invalid catalog revision")
    require(type(document["signer"]) is str and re.fullmatch(HASH_PATTERN, document["signer"]), "invalid catalog signer")
    require(type(document["packages"]) is list and 0 < len(document["packages"]) <= MAX_FILES, "invalid catalog package count")
    ids, urls = set(), set()
    for package in document["packages"]:
        require(type(package) is dict and set(package) == {"id", "version", "url", "bytes", "sha256", "signer", "run_as", "permissions"}, "invalid catalog entry")
        require(type(package["id"]) is str and re.fullmatch(ID_PATTERN, package["id"]) and len(package["id"]) <= 96, "invalid catalog app id")
        _version(package["version"])
        _url(package["url"])
        require(package["id"] not in ids and package["url"] not in urls, "duplicate catalog id or URL")
        ids.add(package["id"])
        urls.add(package["url"])
        require(type(package["bytes"]) is int and 0 < package["bytes"] <= MAX_PACKAGE_BYTES, "invalid catalog package size")
        for field in ("sha256", "signer"):
            require(type(package[field]) is str and re.fullmatch(HASH_PATTERN, package[field]), "invalid catalog hash")
        _permissions(package["permissions"], package["run_as"], allow_root)


def catalog(packages, output, key, base_url, revision, *, package_keys=(), allow_root=False):
    _url(base_url)
    document = {"schema_version": FORMAT_VERSION, "kind": "blade-catalog", "revision": revision,
                "signer": fingerprint(key, private=True), "packages": []}
    with tempfile.TemporaryDirectory(prefix="blade-catalog-") as temporary:
        default_public = Path(temporary) / "publisher.pem"
        default_public.write_bytes(_openssl(["pkey", "-in", str(key), "-passin", "pass:", "-pubout"]))
        trusted_keys = list(package_keys) or [default_public]
        for package in packages:
            verified = None
            for public in trusted_keys:
                try:
                    verified = verify(package, public, allow_root=allow_root)
                    break
                except PackageError:
                    continue
            require(verified is not None, "catalog package is invalid or has no trusted signing key")
            manifest = verified["manifest"]
            document["packages"].append({"id": manifest["id"], "version": manifest["version"],
                "url": base_url.rstrip("/") + "/" + quote(Path(package).name, safe=""),
                "bytes": verified["package_bytes"], "sha256": verified["package_sha256"],
                "signer": manifest["signer"], "run_as": manifest["run_as"], "permissions": manifest["permissions"]})
    document["packages"].sort(key=lambda item: item["id"])
    _catalog(document, allow_root=allow_root)
    signed = {"catalog": document, "signature": base64.b64encode(_signature(canonical(document), key)).decode("ascii")}
    data = canonical(signed)
    require(len(data) <= MAX_METADATA_BYTES, "catalog exceeds size limit")
    _atomic_bytes(output, data)
    return {"revision": revision, "packages": len(packages), "signer": document["signer"]}


def verify_catalog(path, key, *, allow_root=False):
    with Path(path).open("rb") as source:
        envelope = parse_json(source.read(MAX_METADATA_BYTES + 1), exact=True)
    require(set(envelope) == {"catalog", "signature"}, "invalid catalog envelope")
    document = envelope["catalog"]
    _catalog(document, allow_root=allow_root)
    require(hmac.compare_digest(document["signer"], fingerprint(key)), "catalog signer is not trusted")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
    except (ValueError, TypeError) as error:
        raise PackageError("invalid catalog signature encoding") from error
    _signature(canonical(document), key, signature)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("keygen", help="create a local Ed25519 key pair")
    command.add_argument("--private", required=True)
    command.add_argument("--public", required=True)
    command = commands.add_parser("pack", help="create a signed ZIP .bladeapp")
    command.add_argument("--manifest", required=True)
    command.add_argument("--payload", required=True)
    command.add_argument("--output", required=True)
    command.add_argument("--key", required=True, help="unencrypted Ed25519 private key")
    command.add_argument("--allow-root", action="store_true")
    for name in ("verify", "verify-catalog"):
        command = commands.add_parser(name, help="verify with an explicitly trusted public key")
        command.add_argument("path")
        command.add_argument("--key", required=True)
        command.add_argument("--allow-root", action="store_true")
    command = commands.add_parser("catalog", help="create a signed static catalog from verified packages")
    command.add_argument("packages", nargs="+")
    command.add_argument("--output", required=True)
    command.add_argument("--key", required=True)
    command.add_argument("--package-key", action="append", default=[])
    command.add_argument("--base-url", required=True)
    command.add_argument("--revision", required=True, type=int)
    command.add_argument("--allow-root", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "keygen":
            result = keygen(arguments.private, arguments.public)
        elif arguments.command == "pack":
            result = pack(arguments.manifest, arguments.payload, arguments.output, arguments.key, allow_root=arguments.allow_root)
        elif arguments.command == "verify":
            verified = verify(arguments.path, arguments.key, allow_root=arguments.allow_root)
            result = {name: verified["manifest"][name] for name in ("id", "version", "signer", "run_as", "permissions")}
            result.update({"package_sha256": verified["package_sha256"], "package_bytes": verified["package_bytes"]})
        elif arguments.command == "catalog":
            result = catalog(arguments.packages, arguments.output, arguments.key, arguments.base_url,
                             arguments.revision, package_keys=arguments.package_key, allow_root=arguments.allow_root)
        else:
            result = verify_catalog(arguments.path, arguments.key, allow_root=arguments.allow_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PackageError, OSError, ValueError, TypeError, KeyError, struct.error) as error:
        print("blade-sdk: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
