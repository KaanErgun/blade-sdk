import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import blade_sdk as sdk

ROOT = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.private = Path(cls.keys.name) / "private.pem"
        cls.public = Path(cls.keys.name) / "public.pem"
        cls.other_private = Path(cls.keys.name) / "other-private.pem"
        cls.other_public = Path(cls.keys.name) / "other-public.pem"
        sdk.keygen(cls.private, cls.public)
        sdk.keygen(cls.other_private, cls.other_public)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.payload = self.directory / "payload"
        (self.payload / "bin").mkdir(parents=True)
        (self.payload / "bin/hello").write_bytes(b"#!/bin/sh\nprintf 'hello\\n'\n")
        self.metadata = json.loads((ROOT / "examples/hello/app.json").read_text())
        self.metadata_path = self.directory / "app.json"
        self.output = self.directory / "hello.bladeapp"

    def pack(self, *, allow_root=False):
        self.metadata_path.write_text(json.dumps(self.metadata))
        sdk.pack(self.metadata_path, self.payload, self.output, self.private, allow_root=allow_root)
        return self.output

    def mutate_archive(self, transform):
        with zipfile.ZipFile(self.output) as source:
            entries = [(item.filename, source.read(item), item.external_attr >> 16) for item in source.infolist()]
        changed = self.directory / "changed.bladeapp"
        with zipfile.ZipFile(changed, "w") as archive, warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for name, data, mode in transform(entries):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = mode << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
        return changed

    def manifest_mutation(self, mutate, *, resign=False, raw=None):
        def transform(entries):
            manifest = json.loads(next(data for name, data, _ in entries if name == "manifest.json"))
            mutate(manifest)
            encoded = sdk.canonical(manifest) if raw is None else raw(manifest)
            for name, data, mode in entries:
                if name == "manifest.json":
                    data = encoded
                if name == "signature.ed25519" and resign:
                    data = sdk._signature(encoded, self.private)
                yield name, data, mode
        return self.mutate_archive(transform)

    def test_signed_roundtrip_and_deterministic_output(self):
        self.pack()
        result = sdk.verify(self.output, self.public)
        self.assertEqual(result["manifest"]["run_as"], "app")
        self.assertEqual(result["manifest"]["files"]["bin/hello"]["mode"], 0o555)
        other = self.directory / "second.bladeapp"
        sdk.pack(self.metadata_path, self.payload, other, self.private)
        self.assertEqual(other.read_bytes(), self.output.read_bytes())

    def test_missing_permissions_default_to_unprivileged(self):
        del self.metadata["permissions"]
        del self.metadata["run_as"]
        self.pack()
        manifest = sdk.verify(self.output, self.public)["manifest"]
        self.assertEqual(manifest["permissions"], [])
        self.assertEqual(manifest["run_as"], "app")

    def test_never_runs_script(self):
        sentinel = self.directory / "executed"
        (self.payload / "bin/hello").write_text("#!/bin/sh\ntouch '" + str(sentinel) + "'\n")
        self.pack()
        sdk.verify(self.output, self.public)
        self.assertFalse(sentinel.exists())

    def test_wrong_key_and_payload_tamper_rejected(self):
        self.pack()
        with self.assertRaises(sdk.PackageError):
            sdk.verify(self.output, self.other_public)
        changed = self.mutate_archive(lambda entries: [(name, data.replace(b"hello", b"jello") if name == "payload/bin/hello" else data, mode) for name, data, mode in entries])
        with self.assertRaisesRegex(sdk.PackageError, "SHA256"):
            sdk.verify(changed, self.public)

    def test_manifest_tamper_rejected_even_when_canonical(self):
        self.pack()
        changed = self.manifest_mutation(lambda manifest: manifest.update(name="Different application"))
        with self.assertRaises(sdk.PackageError):
            sdk.verify(changed, self.public)

    def test_signed_noncanonical_and_duplicate_json_rejected(self):
        self.pack()
        for raw in (lambda manifest: json.dumps(manifest, indent=2).encode(),
                    lambda manifest: sdk.canonical(manifest).replace(b'"kind":"blade-app"', b'"kind":"blade-app","kind":"blade-app"')):
            with self.subTest(raw=raw):
                changed = self.manifest_mutation(lambda _: None, resign=True, raw=raw)
                with self.assertRaises(sdk.PackageError):
                    sdk.verify(changed, self.public)

    def test_invalid_json_values_and_corrupt_deflate_are_normalized(self):
        for raw in (b'{"value":NaN}', b'{"value":Infinity}', b'{"value":' + b'9' * 5000 + b'}',
                    b'{"value":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}'):
            with self.subTest(raw_prefix=raw[:24]):
                with self.assertRaises(sdk.PackageError):
                    sdk.parse_json(raw, exact=True)
        self.pack()
        with zipfile.ZipFile(self.output) as archive:
            offset = archive.getinfo("payload/bin/hello").header_offset
        data = bytearray(self.output.read_bytes())
        name_size, extra_size = struct.unpack_from("<HH", data, offset + 26)
        data[offset + 30 + name_size + extra_size] = 0xff  # Invalid deflate block type.
        self.output.write_bytes(data)
        with self.assertRaisesRegex(sdk.PackageError, "invalid ZIP"):
            sdk.verify(self.output, self.public)

    def test_traversal_absolute_backslash_and_nul_rejected(self):
        self.pack()
        for path in ("payload/../escape", "/escape", "payload/C:/escape", "payload/a\\b", "payload/a//b", "payload/a/./b", "payload/a\0hidden"):
            with self.subTest(path=path):
                changed = self.mutate_archive(lambda entries: [(path if name == "payload/bin/hello" else name, data, mode) for name, data, mode in entries])
                with self.assertRaises(sdk.PackageError):
                    sdk.verify(changed, self.public)

    def test_duplicate_case_collision_and_unlisted_entry_rejected(self):
        self.pack()
        for name in ("payload/bin/hello", "payload/bin/HELLO", "payload/extra"):
            with self.subTest(name=name):
                changed = self.mutate_archive(lambda entries: entries + [(name, b"extra", stat.S_IFREG | 0o444)])
                with self.assertRaises(sdk.PackageError):
                    sdk.verify(changed, self.public)

    def test_archive_symlink_special_and_setuid_rejected(self):
        self.pack()
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o444, stat.S_IFREG | 0o4755):
            with self.subTest(mode=mode):
                changed = self.mutate_archive(lambda entries: [(name, data, mode if name.startswith("payload/") else original) for name, data, original in entries])
                with self.assertRaises(sdk.PackageError):
                    sdk.verify(changed, self.public)

    def test_source_links_and_special_files_rejected(self):
        (self.payload / "link").symlink_to(self.metadata_path)
        with self.assertRaises(sdk.PackageError):
            self.pack()
        (self.payload / "link").unlink()
        (self.payload / "link").symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(sdk.PackageError):
            self.pack()
        (self.payload / "link").unlink()
        os.mkfifo(self.payload / "fifo")
        with self.assertRaises(sdk.PackageError):
            self.pack()

    def test_root_needs_manifest_permission_and_explicit_acceptance(self):
        self.metadata.update(run_as="root", permissions=["root"])
        with self.assertRaises(sdk.PackageError):
            self.pack()
        self.pack(allow_root=True)
        with self.assertRaises(sdk.PackageError):
            sdk.verify(self.output, self.public)
        self.assertEqual(sdk.verify(self.output, self.public, allow_root=True)["manifest"]["run_as"], "root")

    def test_bad_permissions_version_and_metadata_types_rejected(self):
        baseline = copy.deepcopy(self.metadata)
        for change in ({"run_as": "root"}, {"permissions": ["root"]}, {"permissions": ["hud", "hud"]},
                       {"permissions": ["superuser"]}, {"version": "1.0.0-01"}, {"version": "01.0.0"},
                       {"version": "1.0.0-a..b"}, {"run_as": []}, {"entrypoint_type": []},
                       {"extra": True}, {"source": "https://user:secret@example.test/source"}):
            with self.subTest(change=change):
                self.metadata = {**baseline, **change}
                with self.assertRaises(sdk.PackageError):
                    self.pack(allow_root=True)

    def test_missing_or_invalid_entrypoint_rejected(self):
        for value in (b"echo no shebang\n", b"#!/bin/sh\r\nexit 0\n", b"#!/bin/sh\n\0"):
            (self.payload / "bin/hello").write_bytes(value)
            with self.assertRaises(sdk.PackageError):
                self.pack()
        self.metadata["entrypoint"] = "missing"
        with self.assertRaises(sdk.PackageError):
            self.pack()

    def test_aarch64_elf_and_wrong_arch_or_truncated_segment(self):
        data = bytearray(124)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHIQQ", data, 16, 2, 183, 1, 0x400078, 64)
        struct.pack_into("<HHH", data, 52, 64, 56, 1)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 4096)
        data[120:] = bytes.fromhex("c0035fd6")
        self.metadata["entrypoint_type"] = "elf"
        (self.payload / "bin/hello").write_bytes(data)
        self.pack()
        sdk.verify(self.output, self.public)
        self.output.unlink()
        for offset, value in ((18, struct.pack("<H", 62)), (96, struct.pack("<Q", 100000))):
            changed = bytearray(data)
            changed[offset:offset + len(value)] = value
            (self.payload / "bin/hello").write_bytes(changed)
            with self.assertRaises(sdk.PackageError):
                self.pack()

    def test_source_size_total_count_and_output_cleanup(self):
        for limits in ({"MAX_FILE_BYTES": 4}, {"MAX_PAYLOAD_BYTES": 4}, {"MAX_FILES": 0}, {"MAX_PACKAGE_BYTES": 1}):
            with self.subTest(limits=limits), patch.multiple(sdk, **limits):
                with self.assertRaises(sdk.PackageError):
                    self.pack()
                self.assertFalse(self.output.exists())
        self.assertEqual(list(self.directory.glob(".blade-*")), [])

    def test_compressed_bomb_and_archive_count_rejected_before_read(self):
        self.pack()
        changed = self.mutate_archive(lambda entries: entries + [("payload/bomb", b"\0" * (sdk.MAX_FILE_BYTES + 1), stat.S_IFREG | 0o444)])
        self.assertLess(changed.stat().st_size, 100000)
        with self.assertRaisesRegex(sdk.PackageError, "size limit"):
            sdk.verify(changed, self.public)
        with patch.object(sdk, "MAX_FILES", 0), self.assertRaisesRegex(sdk.PackageError, "entry count"):
            sdk.verify(self.output, self.public)

    def test_signed_manifest_limits_and_file_directory_conflicts(self):
        self.pack()
        mutations = [lambda m: m["files"]["bin/hello"].update(bytes=sdk.MAX_FILE_BYTES + 1),
                     lambda m: m["files"].update(bin={"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "mode": 0o444}),
                     lambda m: m.update(schema_version=True)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = self.manifest_mutation(mutation, resign=True)
                with self.assertRaises(sdk.PackageError):
                    sdk.verify(changed, self.public)

    def test_tar_and_gzip_tar_explicitly_unsupported(self):
        for mode in ("w", "w:gz"):
            output = self.directory / ("unsafe-" + mode.replace(":", "") + ".bladeapp")
            with tarfile.open(output, mode) as archive:
                item = tarfile.TarInfo("../escape")
                item.type = tarfile.SYMTYPE
                item.linkname = "/etc/passwd"
                archive.addfile(item)
            with self.assertRaisesRegex(sdk.PackageError, "only ZIP"):
                sdk.verify(output, self.public)

    def test_existing_outputs_preserved_and_payload_output_forbidden(self):
        self.pack()
        before = self.output.read_bytes()
        with self.assertRaises(sdk.PackageError):
            self.pack()
        self.assertEqual(self.output.read_bytes(), before)
        self.output = self.payload / "recursive.bladeapp"
        with self.assertRaises(sdk.PackageError):
            self.pack()

    def test_zip_truncation_comment_and_signature_length_rejected(self):
        self.pack()
        changed = self.directory / "broken.bladeapp"
        for content in (self.output.read_bytes()[:-4], self.output.read_bytes() + b"trailing"):
            changed.write_bytes(content)
            with self.assertRaises(sdk.PackageError):
                sdk.verify(changed, self.public)
        changed = self.mutate_archive(lambda entries: [(name, b"bad" if name == "signature.ed25519" else data, mode) for name, data, mode in entries])
        with self.assertRaises(sdk.PackageError):
            sdk.verify(changed, self.public)

    def test_catalog_roundtrip_and_independent_package_publisher(self):
        self.pack()
        output = self.directory / "catalog.json"
        sdk.catalog([self.output], output, self.other_private, "https://example.test/apps", 3, package_keys=[self.public])
        catalog = sdk.verify_catalog(output, self.other_public)
        self.assertEqual(catalog["revision"], 3)
        self.assertEqual(catalog["packages"][0]["sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(catalog["packages"][0]["signer"], sdk.fingerprint(self.public))
        with self.assertRaises(sdk.PackageError):
            sdk.verify_catalog(output, self.public)
        before = output.read_bytes()
        with self.assertRaises(FileExistsError):
            sdk.catalog([self.output], output, self.private, "https://example.test/apps", 4)
        self.assertEqual(output.read_bytes(), before)

    def test_catalog_tamper_duplicate_revision_and_untrusted_package(self):
        self.pack()
        output = self.directory / "catalog.json"
        for packages, revision, private in (([self.output, self.output], 1, self.private), ([self.output], 0, self.private),
                                            ([self.output], 1, self.other_private)):
            with self.assertRaises(sdk.PackageError):
                sdk.catalog(packages, output, private, "https://example.test/apps", revision)
            self.assertFalse(output.exists())
        sdk.catalog([self.output], output, self.private, "https://example.test/apps", 1)
        data = json.loads(output.read_bytes())
        data["catalog"]["packages"][0]["url"] = "https://example.test/changed"
        output.write_bytes(sdk.canonical(data))
        with self.assertRaises(sdk.PackageError):
            sdk.verify_catalog(output, self.public)

    def test_root_catalog_requires_explicit_acceptance(self):
        self.metadata.update(run_as="root", permissions=["root"])
        self.pack(allow_root=True)
        output = self.directory / "catalog.json"
        with self.assertRaises(sdk.PackageError):
            sdk.catalog([self.output], output, self.private, "https://example.test/apps", 1)
        sdk.catalog([self.output], output, self.private, "https://example.test/apps", 1, allow_root=True)
        with self.assertRaises(sdk.PackageError):
            sdk.verify_catalog(output, self.public)
        self.assertEqual(sdk.verify_catalog(output, self.public, allow_root=True)["packages"][0]["run_as"], "root")

    def test_schema_contract_matches_validator_and_limits(self):
        manifest = json.loads((ROOT / "schemas/manifest-v1.schema.json").read_text())
        catalog = json.loads((ROOT / "schemas/catalog-v1.schema.json").read_text())
        properties = manifest["properties"]
        catalog_properties = catalog["properties"]["catalog"]["properties"]
        package_properties = catalog_properties["packages"]["items"]["properties"]
        self.assertEqual(set(manifest["required"]), sdk.MANIFEST_FIELDS)
        self.assertEqual(set(properties), sdk.MANIFEST_FIELDS)
        self.assertEqual(properties["schema_version"]["const"], sdk.FORMAT_VERSION)
        self.assertEqual(catalog_properties["schema_version"]["const"], sdk.FORMAT_VERSION)
        self.assertEqual(properties["files"]["maxProperties"], sdk.MAX_FILES)
        self.assertEqual(properties["files"]["additionalProperties"]["properties"]["bytes"]["maximum"], sdk.MAX_FILE_BYTES)
        self.assertEqual(catalog_properties["packages"]["maxItems"], sdk.MAX_FILES)
        self.assertEqual(package_properties["bytes"]["maximum"], sdk.MAX_PACKAGE_BYTES)
        self.assertEqual(set(properties["permissions"]["items"]["enum"]), sdk.PERMISSIONS)
        self.assertEqual(set(package_properties["permissions"]["items"]["enum"]), sdk.PERMISSIONS)
        self.assertEqual(properties["id"]["pattern"], "^" + sdk.ID_PATTERN + "$")
        self.assertEqual(manifest["$defs"]["path"]["pattern"], "^" + sdk.PATH_PATTERN + "$")
        self.assertFalse(manifest["additionalProperties"])
        self.assertFalse(catalog["additionalProperties"])

    def test_cli_failure_is_bounded_and_reports_no_success(self):
        invalid = self.directory / "invalid.bladeapp"
        invalid.write_bytes(b"not a package")
        result = subprocess.run([sys.executable, str(ROOT / "blade_sdk.py"), "verify", str(invalid), "--key", str(self.public)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn("Traceback", result.stderr)
        version = subprocess.run([sys.executable, str(ROOT / "blade_sdk.py"), "--version"], capture_output=True, text=True, timeout=15)
        self.assertEqual(version.returncode, 0)
        self.assertEqual(version.stdout.strip(), sdk.VERSION)

    def test_key_permissions_reuse_and_non_ed25519(self):
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o600)
        before = self.private.read_bytes()
        with self.assertRaises(sdk.PackageError):
            sdk.keygen(self.private, self.public)
        self.assertEqual(self.private.read_bytes(), before)
        key = self.directory / "ec.pem"
        sdk._openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)])
        with self.assertRaises(sdk.PackageError):
            sdk.fingerprint(key, private=True)

    def test_real_cli_example_pack_verify_catalog(self):
        def cli(*arguments):
            result = subprocess.run([sys.executable, str(ROOT / "blade_sdk.py"), *map(str, arguments)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        output = self.directory / "example.bladeapp"
        cli("pack", "--manifest", ROOT / "examples/hello/app.json", "--payload", ROOT / "examples/hello/payload",
            "--output", output, "--key", self.private)
        self.assertEqual(cli("verify", output, "--key", self.public)["id"], "dev.kaanergun.hello")
        catalog = self.directory / "catalog.json"
        cli("catalog", output, "--output", catalog, "--key", self.private, "--base-url", "https://example.test/apps", "--revision", "1")
        self.assertEqual(cli("verify-catalog", catalog, "--key", self.public)["revision"], 1)


if __name__ == "__main__":
    unittest.main()
