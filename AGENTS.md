# Repository rules

- This SDK packages and verifies applications; it never extracts, installs, or runs them. Device endpoints are outside this repository until a measured OS API exists.
- The canonical local gate is `./scripts/check.sh`. No hosted CI, workflow, registry, or publication automation.
- Keep the Python API framework independent. Python standard library and the existing OpenSSL 3 CLI are the only runtime requirements.
- Manifest/catalog format versions, schemas, limits, and validators must agree; test their parity. Verification uses an externally supplied trusted Ed25519 public key.
- No firmware, vendor decompile, private keys, credentials, personal media, or device identifiers in git. Test keys are temporary.
- Source, comments, and public README are English; internal plans/status are Turkish. `docs/durum.md` is the sole living status document.
- MIT license, copyright Kaan Ergün. Identify the project as unofficial; do not imply Vuzix endorsement.
