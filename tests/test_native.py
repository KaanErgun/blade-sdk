"""Cross-language package acceptance and hostile archive fixtures."""
import hashlib
import os
import re
import math
from pathlib import Path
import subprocess
import tempfile
import unittest

import blade_sdk as sdk
import test_sdk as fixtures


class NativeTests(fixtures.PackageTests):
    # Exercise the existing signed fixture builders, without duplicating their tests.
    def native(self, path=None, *, valid=True, key=None, root=False):
        binary = os.environ.get("BLADE_VERIFY")
        self.assertTrue(binary, "canonical gate must compile BLADE_VERIFY first")
        der = self.directory / "trusted.der"
        der.write_bytes(sdk.public_der(key or self.public))
        result = subprocess.run([binary, str(path or self.output), str(der),
                                 *(["--allow-root"] if root else [])],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0 if valid else 2, result.stderr.decode())
        return result

    def test_native_roundtrip_unicode_and_stored(self):
        self.metadata["name"] = "Örnek gözlük 🎉"
        self.pack()
        self.native()
        stored = self.mutate_archive(lambda entries: entries)
        self.native(stored)

    def test_native_external_key_and_signature(self):
        self.pack()
        self.native(key=self.other_public, valid=False)
        bad = self.mutate_archive(lambda entries: [(n, b"x" * 64 if n == "signature.ed25519" else d, m) for n, d, m in entries])
        self.native(bad, valid=False)

    def test_native_signed_manifest_rejections(self):
        self.pack()
        mutations = [
            lambda m: m.update(id="../../escape"),
            lambda m: m.update(version="1.0.0-01"),
            lambda m: m.update(target="linux-x86_64"),
            lambda m: m.update(entrypoint="../../outside"),
            lambda m: m.update(permissions=["network", "network"]),
            lambda m: m.update(permissions=["unknown"]),
            lambda m: m.update(extra="field"),
            lambda m: m["files"]["bin/hello"].update(bytes=2**32),
            lambda m: m["files"]["bin/hello"].update(mode=0o4755),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                bad = self.manifest_mutation(mutate, resign=True)
                self.native(bad, valid=False)

    def test_native_canonical_json(self):
        self.pack()
        for raw in (lambda m: sdk.canonical(m).replace(b'"kind":"blade-app"', b'"kind":"blade-app","kind":"blade-app"'),
                    lambda m: sdk.canonical(m).replace(b'"entrypoint":', b'"entrypoint" :'),
                    lambda m: sdk.canonical(m).replace(b"blade-app", b"blade-\\u0061pp"),
                    lambda m: sdk.canonical(m) + b"\n"):
            bad = self.manifest_mutation(lambda _: None, resign=True, raw=raw)
            self.native(bad, valid=False)

    def test_native_root_requires_owner_opt_in(self):
        self.metadata.update(run_as="root", permissions=["root"])
        self.pack(allow_root=True)
        self.native(valid=False)
        self.native(root=True)

    def test_native_zip_boundaries(self):
        self.pack()
        raw = self.output.read_bytes()
        for data in (raw[:10], raw[:-1], raw + b"x", b"x" + raw,
                     raw[:6] + b"\x01\x00" + raw[8:]):
            self.output.write_bytes(data)
            self.native(valid=False)
        self.output.write_bytes(raw)
        for index in (0, 14, 18, 22, 26, 28, len(raw) - 22, len(raw) - 6):
            changed = bytearray(raw); changed[index] ^= 0x40
            self.output.write_bytes(changed)
            self.native(valid=False)

    def test_native_payload_and_paths(self):
        self.pack()
        for transform in (
            lambda entries: [(n, d + b"x" if n.startswith("payload/") else d, m) for n, d, m in entries],
            lambda entries: [("payload/../escape" if n.startswith("payload/") else n, d, m) for n, d, m in entries],
            lambda entries: entries + [entries[0]],
            lambda entries: [(n, d, 0o120777 if n.startswith("payload/") else m) for n, d, m in entries],
        ):
            self.native(self.mutate_archive(transform), valid=False)

    def test_native_limits_match_python_contract(self):
        header = (fixtures.ROOT / "native/package.h").read_text()
        for native, python in (("MAX_PACKAGE", "MAX_PACKAGE_BYTES"), ("MAX_PAYLOAD", "MAX_PAYLOAD_BYTES"),
                               ("MAX_FILE", "MAX_FILE_BYTES"), ("MAX_METADATA", "MAX_METADATA_BYTES"),
                               ("MAX_FILES", "MAX_FILES")):
            value = re.search(r"^#define BP_" + native + r" ([0-9u *()]+)$", header, re.M)
            self.assertIsNotNone(value)
            actual = math.prod(int(n) for n in re.findall(r"\d+", value[1]))
            self.assertEqual(actual, getattr(sdk, python))


# Reuse setup/helpers, not the 28 Python-only methods inherited from PackageTests.
for _name in dir(fixtures.PackageTests):
    if _name.startswith("test_"):
        setattr(NativeTests, _name, None)


if __name__ == "__main__":
    unittest.main()
