# Known-answer vectors

`primitives.json` — HKDF32, SIV and Argon2id, used by each language's own unit tests.

`auto-mode.json` — inputs (hex) and the mode that `--mode auto` must pick for each: `lines`
for text (no NUL byte, well-formed UTF-8), `blob` for anything else. Used by each
language's unit tests and by the `auto` suite of the cross tests.

Every other directory is a file-level vector: `plain.bin` and `encrypted.txt`.
`vectors.json` says which key opens each one (`password`, or `ssh` = a key in `tests/keys/`).
For every implementation both of these must hold:

    decrypt(encrypted.txt)                              == plain.bin
    encrypt(plain.bin, previous = encrypted.txt)        == encrypted.txt   (byte for byte)

The second works without any test hook because encryption is deterministic once the data
key and slots are taken from `previous`.
