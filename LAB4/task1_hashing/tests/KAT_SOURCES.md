# LAB4 KAT Sources

This directory contains the known-answer tests used by `kat_vectors.json`.

## Official sources

- `shabytetestvectors.zip`
  - NIST CAVP SHS byte-oriented test vectors.
  - URL: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
  - Used for SHA-224, SHA-256, SHA-384, SHA-512.
  - Extracted files used: `ShortMsg.rsp` and `LongMsg.rsp`.

- `sha3bytetestvectors.zip`
  - NIST CAVP SHA-3 byte-oriented test vectors.
  - URL: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
  - Used for SHA3-224, SHA3-256, SHA3-384, SHA3-512.
  - Extracted files used: `ShortMsg.rsp` and `LongMsg.rsp`.

## Standards

- NIST FIPS 180-4: Secure Hash Standard (SHS).
  - URL: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
- NIST FIPS 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions.
  - URL: https://csrc.nist.gov/pubs/fips/202/final

## Coverage

`kat_vectors.json` contains 1662 one-shot KAT cases:

- SHA-224: 129 cases
- SHA-256: 129 cases
- SHA-384: 257 cases
- SHA-512: 257 cases
- SHA3-224: 245 cases
- SHA3-256: 237 cases
- SHA3-384: 205 cases
- SHA3-512: 173 cases
- SHAKE128: 15 cases
- SHAKE256: 15 cases

The SHA-2 and SHA-3 fixed-output cases are converted directly from NIST CAVP
`.rsp` files. For `Len = 0`, CAVP writes `Msg = 00`; this is interpreted as an
empty message in JSON.

SHAKE128 and SHAKE256 are XOFs, so the JSON includes multiple output lengths
for representative messages. Expected values are generated from the FIPS 202
SHAKE definition with Python `hashlib`, including the standard empty-message
examples. These SHAKE entries are reproducible FIPS 202 conformance vectors,
not converted CAVP `.rsp` files.

Monte Carlo `.rsp` files are preserved in the extracted source directories, but
they are not included in `kat_vectors.json` because the current LAB4 KAT runner
supports independent one-shot test cases only.
