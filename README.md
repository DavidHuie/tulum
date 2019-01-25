# Tulum

<p align="center">
    <img src="https://github.com/DavidHuie/tulum/raw/master/images/tulum.jpg" width="50%" height="50%">
</p>

Tulum is a simple tool for encrypting and decrypting data without any
knowledge of cryptography. Tulum only has two, zero-configuration
operations, preventing confusion and user error. Tulum was designed
to adhere to the [UNIX philosophy](https://en.wikipedia.org/wiki/Unix_philosophy)
by both being composable and doing one thing well.

Tulum's provides sane defaults for most users. For cryptography, Tulum
uses 256-bit AES-CTR encryption with HMAC-SHA-256 in an
encrypt-then-MAC configuration, which provides authenticated
encryption (decryption fails if an adversary modifies the encrypted
data). Additionally, Tulum always generates a new key for each
encryption operation, preventing key reuse. Tulum uses stdin and
stdout for IO operations, allowing the user to extend Tulum with other
Unix CLI tools.

## Installation

With Go 1.11+, Tulum can be installed as follows:
```shell
go get -u github.com/DavidHuie/tulum
```

## Usage

```text
% tulum -h
Usage of tulum:
  -dec
    	decrypt from stdin, writing output to stdout
  -enc
    	encrypt from stdin, writing output to stdout
  -key string
    	the path to the key
```

To encrypt the file `f`, storing the key in `key.asc` and the
ciphertext (the encrypted file) in `f.enc`:
```shell
% cat f | tulum > f.enc
```

Optionally, to encrypt the file `f`, storing the key in `my-key.asc`
and the ciphertext in `f.enc`:
```shell
% cat f | tulum -key my-key.asc > f.enc
```

To decrypt the file `f.enc` with the key `key.asc`:
```shell
% cat f.enc | tulum -dec > f.dec
```

Optionally, to decrypt the file `f.enc` with the key `my-key.asc`:
```shell
% cat f.enc | tulum -dec -key my-key.asc > f.dec
```
