# Third-party provenance

Ascon source: https://github.com/ascon/ascon-c
Commit: `446347f21b209f3921c65ece70027c366cbe1693`
Retrieved for this project on 2026-10-26.

Copied `crypto_aead/asconaead128/ref/*`, `tests/crypto_aead.h`, and `crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt` (stored as `test_vectors/ascon_kat.txt`). Source contents are unmodified. Upstream license files are included in this directory. The algorithm is the final NIST SP 800-232 Ascon-AEAD128, not an older competition version. All 1089 encryption vectors and corresponding decryption round trips were executed by the test suite.

pqcrypto is installed from its pinned PyPI wheel via requirements.txt. ML-KEM-512 uses `keygen`, `encaps`, `decaps` from `pqcrypto.kem.ml_kem_512` in version 1.0.0. No vendored, handwritten ML-KEM implementation is claimed. Secret agreement tests are integration checks, not FIPS module certification.

The project’s original CAALC code is provided under the MIT license in the project root. Third-party files retain their upstream licenses.
