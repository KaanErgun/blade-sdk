"""Validate the public language-neutral owner protocol fixture without a device."""
from pathlib import Path
import re
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ProtocolFixtureTests(unittest.TestCase):
    def test_canonical_fixture_and_signed_permission_bits(self):
        data = (ROOT / 'docs/bld1-v1.properties').read_bytes()
        self.assertTrue(data.endswith(b'\n'))
        values = {}
        for line in data.decode('ascii').splitlines():
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                self.assertNotIn(key, values)
                values[key] = value
        self.assertEqual(len(values), 46)
        header = (ROOT / 'native/package.h').read_text()
        for name in ('HUD', 'NETWORK', 'STORAGE'):
            match = re.search(r'^#define BP_' + name + r' (\d+)u$', header, re.M)
            self.assertIsNotNone(match)
            self.assertEqual(values['market.' + name], match[1])
        names = ('START', 'TEXT', 'ARROW', 'AUTH_MANAGEMENT', 'UPLOAD_CHUNK', 'INSTALL', 'ACTION')
        types = (3, 7, 8, 20, 34, 37, 38)
        for index, (name, kind) in enumerate(zip(names, types)):
            encoded = values['wire.' + name]
            self.assertRegex(encoded, r'^[0-9a-f]+$')
            packet = bytes.fromhex(encoded)
            self.assertEqual(struct.unpack('>4sHHII', packet[:16]),
                             (b'BLD1', 1, kind, 0x10203040 + index, len(packet) - 16))
        text = bytes.fromhex(values['wire.TEXT'])[16:]
        self.assertEqual(int.from_bytes(text[24:26], 'big'), len(text[26:]))
        self.assertEqual(text[26:].decode('utf8'), 'Yön')
        install = bytes.fromhex(values['wire.INSTALL'])[16:]
        self.assertEqual(int.from_bytes(install[16:20], 'big'), 4 | 8 | 16)
        self.assertEqual(install[20:], bytes(range(64, 96)))


if __name__ == '__main__':
    unittest.main()
