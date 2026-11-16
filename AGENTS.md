# Repository rules

- The Python SDK packages and verifies applications. The native library verifies the same format and extracts only verified payloads into a caller-owned staging directory; OS lifecycle, privilege enforcement and device endpoints belong to Blade OS.
- The canonical local gate is `./scripts/check.sh`. No hosted CI, workflow, registry, or publication automation.
- Keep the Python API framework independent. Python uses its standard library and OpenSSL 3 CLI; native verification uses OpenSSL 3 libcrypto and zlib. Never implement replacement cryptography.
- Manifest/catalog format versions, schemas, limits, and validators must agree; test their parity. Verification uses an externally supplied trusted Ed25519 public key.
- `docs/bld1-v1.properties` is the canonical public owner-protocol golden fixture. OS compiled-code parity and Android's byte-identical test-resource copy must change together; future Swift tests consume the same bytes. Package grants remain separate from owner pairing credentials.
- No firmware, vendor decompile, private keys, credentials, personal media, or device identifiers in git. Test keys are temporary.
- Source, comments, and public README are English; internal plans/status are Turkish. `docs/durum.md` is the sole living status document.
- MIT license, copyright Kaan Ergün. Identify the project as unofficial; do not imply Vuzix endorsement.
