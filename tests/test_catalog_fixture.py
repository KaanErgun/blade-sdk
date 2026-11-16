import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("catalog_fixture_sdk", ROOT / "blade_sdk.py")
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


class CatalogFixtureTests(unittest.TestCase):
    def test_real_sdk_signed_catalog_and_independent_publisher(self):
        fixtures = ROOT / "tests/fixtures"
        catalog = sdk.verify_catalog(fixtures / "catalog-v1.json", fixtures / "catalog-publisher.pem")
        self.assertEqual(catalog["revision"], 7)
        self.assertEqual(catalog["packages"][0]["id"], "dev.kaanergun.hello")
        self.assertEqual(catalog["packages"][0]["permissions"], ["hud"])
        self.assertNotEqual(catalog["signer"], catalog["packages"][0]["signer"])


if __name__ == "__main__":
    unittest.main()
