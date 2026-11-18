# Argon2id

Safe Deposit Box never uses your passphrase directly as an encryption key.
It first runs the passphrase through **Argon2id**, a *password-based key derivation
function* (KDF). This page explains what that is and why it matters.

## The problem it solves
Encryption algorithms such as ChaCha20 need a key of exactly 256 random-looking bits.
A passphrase is neither the right length nor random: people choose words, names and
patterns, so the number of likely passphrases is far smaller than 2²⁵⁶.

An attacker who steals an encrypted file can try passphrases offline, as fast as their
hardware allows. With a fast hash such as SHA-256, a single GPU can test billions of
guesses per second. A KDF makes every guess expensive, which turns "billions per second"
into "a handful per second".

## What Argon2id is
Argon2 won the [Password Hashing Competition](https://www.password-hashing.net/) in 2015
and is standardised in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106). It comes in
three variants:

| Variant | Memory access pattern | Strength |
|---------|-----------------------|----------|
| Argon2d | depends on the passphrase | best resistance to GPU/ASIC cracking, but can leak information through cache-timing side channels |
| Argon2i | independent of the passphrase | side-channel resistant, but weaker against cracking hardware |
| **Argon2id** | hybrid: Argon2i for the first pass, then Argon2d | gets most of the benefit of both; **the variant RFC 9106 recommends** |

### Memory-hardness
Argon2's key idea is that it is **memory-hard**. Computing one key requires filling a
large block of memory (64 MiB in SDB) with pseudo-random data, then reading it back in
an unpredictable order. Skipping the memory makes the computation drastically slower.

This matters because attackers scale up by running many guesses in parallel:

- A **CPU** has plenty of memory, so one legitimate unlock takes a fraction of a second.
- A **GPU** has thousands of cores but only a few GB of fast memory. At 64 MiB per guess,
  only a small number of guesses fit at once, so most of the cores sit idle.
- Custom **ASICs** cannot cheat either. Memory costs silicon area and money, no matter
  how clever the circuit is.

## Parameters
Argon2id has three cost knobs. SDB uses the
[RFC 9106 second recommended option](https://www.rfc-editor.org/rfc/rfc9106#section-4),
which is intended for interactive use where memory is limited:

| Parameter | SDB default | Meaning |
|-----------|-------------|---------|
| `t` time | 3 | number of passes over the memory |
| `m` memory | 64 MiB | amount of memory filled per derivation |
| `p` parallelism | 4 | number of lanes computed in parallel |
| salt | 16 random bytes | unique per file |
| output | 32 bytes | the 256-bit key-encryption key |

The parameters are **stored in each file's header**, so files stay readable if the
defaults are raised in future versions.

When reading a file, SDB checks the stored parameters against hard limits before running
Argon2id (time ≤ 64, 8 MiB ≤ memory ≤ 4 GiB, threads ≤ 64). Without that check, a
maliciously crafted file could demand terabytes of memory. The parameters are also
authenticated, so changing them only produces a "wrong passphrase" error.

## The salt
Each file gets a fresh random 16-byte salt, which is mixed into the derivation. As a
result:

- the same passphrase produces a **different key for every file**;
- an attacker cannot precompute a table of "passphrase → key" and reuse it across files
  (a rainbow table); each file has to be attacked separately.

The salt is not secret, and it is stored in plain form in the header.

## How SDB uses the derived key
The Argon2id output is a **key-encryption key (KEK)**. It never encrypts your data
directly. Instead it encrypts a random per-file **data key**, which does the bulk
encryption (see [architecture.md](architecture.md)). Benefits of this split:

- Argon2id runs **once per file**, not once per chunk, so it adds a fixed ~0.1–0.3 s
  rather than slowing down large files.
- The data key is truly random and full-strength, whatever the passphrase quality.
- Future features such as changing the passphrase or adding extra unlock methods only
  need to re-wrap the 32-byte data key, not re-encrypt the whole file.

## What Argon2id cannot do
A KDF slows guessing down but cannot make a weak passphrase strong. A passphrase that
appears in a breach list or dictionary will still fall. Use a long passphrase, ideally
four to six random words or a password-manager-generated string. SDB warns when a
passphrase is shorter than 12 characters.

## In the code
- [`key-mgt/kdf.go`](../key-mgt/kdf.go): `DeriveKey`, parameter validation, salt
  generation, memory wiping.
- [`safe/header.go`](../safe/header.go): `newHeader` and `unwrap` use the derived KEK to
  wrap and unwrap the data key.
- Implementation: [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2),
  the Go team's maintained implementation.
