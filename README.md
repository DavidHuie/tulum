# Tulum

<p align="center">
    <img src="https://github.com/DavidHuie/tulum/raw/master/images/tulum.jpg" width="50%" height="50%">
</p>

Tulum is a simple tool for encrypting and decrypting data without any
knowledge of cryptography. Tulum only has two, zero configuration
operations, preventing confusion and user error. By default, Tulum
uses 128-bit AES-GCM encryption, which provides both encryption and
authentication (decryption fails if the encrypted data is
modified). Additionally, Tulum always generates a new key for each
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
Usage of ./tulum:
  -dec
    	decrypt from stdin, writing output to stdout
  -enc
    	encrypt from stdin, writing output to stdout
  -key string
    	the path to the key
```

To encrypt the file `f`, storing the key in `key.asc`:
```shell
% cat f | tulum -key key.asc -enc > f.enc
```

To decrypt the file `f.enc` with the key `key.asc`:
```shell
% cat f.enc | tulum -key key.asc -dec > f.dec
```
