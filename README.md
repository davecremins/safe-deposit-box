# Safe Deposit Box [![pipeline status](https://gitlab.com/davecremins/safe-deposit-box/badges/master/pipeline.svg)](https://gitlab.com/davecremins/safe-deposit-box/commits/master)[![coverage report](https://gitlab.com/davecremins/safe-deposit-box/badges/master/coverage.svg)](https://gitlab.com/davecremins/safe-deposit-box/commits/master)[![Go Report Card](https://goreportcard.com/badge/gitlab.com/davecremins/safe-deposit-box)](https://goreportcard.com/report/gitlab.com/davecremins/safe-deposit-box)

## Description
Safe deposit box (SDB) is a tool that secures data. Security of data is provided through the use of industry standard encryption algorithms and schemes. 
SDB can be used to: 
- Secure keys, creds, secrets, etc. 
- Encrypt data before it is persisted 
- Generate on the fly keys that will have specific lease periods
- Encrypt data without storing it

## Installation
Requires Go 1.22 or newer.

```sh
go install gitlab.com/davecremins/safe-deposit-box@latest   # or: go build -o sdb .
```

## Usage
```sh
sdb encrypt secrets.txt              # writes secrets.txt.sdb, prompts for a passphrase twice
sdb decrypt secrets.txt.sdb          # writes secrets.txt
sdb encrypt -o vault.sdb notes.md    # choose the output path
tar cz docs | sdb encrypt > docs.tgz.sdb
sdb decrypt docs.tgz.sdb -o - | tar xz
sdb decrypt -passphrase-file pw.txt backup.sdb   # non-interactive use
```

| Flag | Meaning |
|------|---------|
| `-o PATH` | output path (`-` for stdout) |
| `-f` | overwrite an existing output file |
| `-passphrase-file PATH` | read the passphrase from the first line of a file instead of the terminal |

The original file is left in place after encryption. Deleting it securely is up to you,
because overwriting files in place is unreliable on SSDs and journaling or copy-on-write
filesystems.

## How it works
SDB uses *envelope encryption*, like a bank vault: your passphrase opens the box,
and the box holds the key that locks your data.

1. A fresh random 256-bit **data key** is generated for every file.
2. The data is encrypted with **ChaCha20-Poly1305** in 64 KiB authenticated chunks
   (the STREAM construction). Memory use stays flat for any file size, and modified,
   reordered or truncated data is rejected.
3. The data key is encrypted ("wrapped") with **XChaCha20-Poly1305**. The wrapping key
   is derived from your passphrase with **Argon2id** (t=3, m=64 MiB, p=4, per RFC 9106)
   and a random salt.
4. Only the wrapped key is stored in the file header, and the whole header is
   authenticated. Neither the passphrase nor any usable key is ever written to disk,
   and keys are wiped from memory after use.

When the output is a file, it is first written to a temporary file with `0600`
permissions and renamed into place only after every chunk has been verified.
When decrypting to stdout, data is streamed as it is verified. If decryption
fails partway, any output already written must be discarded.

### File format (v1)
| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 3 | magic `SDB` |
| 3 | 1 | version `1` |
| 4 | 1 | KDF id (`1` = Argon2id) |
| 5 | 4 | Argon2id time cost (big-endian) |
| 9 | 4 | Argon2id memory, KiB (big-endian) |
| 13 | 1 | Argon2id threads |
| 14 | 16 | salt |
| 30 | 24 | key-wrap nonce |
| 54 | 48 | wrapped data key + tag |
| 102 | … | payload chunks, each up to 64 KiB of ciphertext plus a 16-byte tag |

Chunk nonces are an 88-bit big-endian counter followed by a flag byte, which is `1`
only on the final chunk.

## Development
```sh
make test          # run tests with the race detector and print coverage
make cover-check   # fail if total coverage is below 80%
make bench         # encryption throughput benchmark
```
