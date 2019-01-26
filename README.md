# Tulum

<p align="center">
    <img src="https://github.com/DavidHuie/tulum/raw/master/images/tulum.jpg" width="50%" height="50%">
</p>

[![CircleCI](https://circleci.com/gh/DavidHuie/tulum.svg?style=svg)](https://circleci.com/gh/DavidHuie/tulum)

Tulum is a simple tool for encrypting and decrypting data without any
knowledge of cryptography. Tulum has only two, zero-configuration
operations, preventing confusion and user error. Tulum was designed to
adhere to the [UNIX
philosophy](https://en.wikipedia.org/wiki/Unix_philosophy) by both
being composable and doing one thing well. In comparison to tools like
OpenSSL and GPG, Tulum is considerably easier to use for symmetric
encryption.

Tulum's provides sane defaults for most users. For cryptography, Tulum
uses 256-bit AES-CTR encryption, HMAC-SHA-256 in an encrypt-then-MAC
configuration, which provides authenticated encryption (decryption
fails if an adversary modifies the encrypted data), and
HKDF-SHA-256. Additionally, Tulum always generates a new key for each
encryption operation, preventing key reuse. Tulum uses stdin and
stdout for IO operations, allowing the user to extend Tulum with other
Unix CLI tools.

## Background

Tulum performs symmetric encryption, where a random string, called a
key, is used to both encrypt and decrypt data. Without the key, it is
practically impossible to decrypt an encrypted payload, providing the
privacy features people expect. Tulum generates keys automatically, so
keys are only really useful for decryption.

Since the key enables decryption of your data, *store keys safely*!
Keys should not be transferred with the encrypted data, and they
should not be visible to other users on your computer (keys are
assigned file attributes of `0600` by default). Additionally, Tulum
generates a unique key for each encryption operation, so make sure
that keys aren't confused between encrypted payloads.

## Installation

With Go 1.11+, Tulum can be installed as follows:
```shell
go get -u github.com/DavidHuie/tulum
```

## Usage

```text
% tulum -h
Tulum is a simple, fast, zero-configuration file encryption tool.

Tulum uses the following cryptography:
  Encryption: AES-256 in counter mode
  MAC: HMAC with SHA-256
  Key derivation: HKDF with SHA-256

Usage:
  tulum [flags] [file]

Flags:
  -dec
    	decrypt from file argument or stdin, writing output to stdout
  -enc
    	encrypt from file argument or stdin, writing output to stdout (default true)
  -key string
    	the path to the key (default "key.asc")
```

To encrypt the file `f`, storing the key in `key.asc` and the
ciphertext (the encrypted file) in `f.enc`:
```shell
% tulum f > f.enc
# Or
% cat f | tulum > f.enc
```

Optionally, to encrypt the file `f`, storing the key in `my-key.asc`
and the ciphertext in `f.enc`:
```shell
% tulum -key my-key.asc f > f.enc
# Or
% cat f | tulum -key my-key.asc > f.enc
```

To decrypt the file `f.enc` with the key `key.asc`:
```shell
% tulum -dec f.enc > f.dec
# Or
% cat f.enc | tulum -dec > f.dec
```

Optionally, to decrypt the file `f.enc` with the key `my-key.asc`:
```shell
% tulum -dec -key my-key.asc f.enc > f.dec
# Or
% cat f.enc | tulum -dec -key my-key.asc > f.dec
```
