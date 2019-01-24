package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
)

const (
	keySizeBytes   = 16
	nonceSizeBytes = 12
)

func encrypt(r io.Reader, w io.Writer, keyPath string) error {
	key, err := generateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := persistKey(key, keyPath); err != nil {
		return err
	}

	ciph, err := aes.NewCipher(key.key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(ciph)
	if err != nil {
		return err
	}

	pt, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	out := hex.NewEncoder(w)
	ct := aead.Seal(nil, key.nonce, pt, nil)
	if _, err := io.Copy(out, bytes.NewBuffer(ct)); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}

	return nil
}

func decrypt(r io.Reader, w io.Writer, keyPath string) error {
	key, err := getKey(keyPath)
	if err != nil {
		return err
	}
	ctHex, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	trimmed := bytes.Trim(ctHex, "\n")
	ct := make([]byte, len(trimmed)/2)
	if _, err := hex.Decode(ct, trimmed); err != nil {
		return err
	}

	ciph, err := aes.NewCipher(key.key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(ciph)
	if err != nil {
		return err
	}

	pt, err := aead.Open(nil, key.nonce, ct, nil)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(pt)); err != nil {
		return err
	}

	return nil
}

type key struct {
	key   []byte
	nonce []byte
}

func generateKey(r io.Reader) (*key, error) {
	k, n := &bytes.Buffer{}, &bytes.Buffer{}
	if _, err := io.CopyN(k, r, keySizeBytes); err != nil {
		return nil, err
	}
	if _, err := io.CopyN(n, r, nonceSizeBytes); err != nil {
		return nil, err
	}
	return &key{
		key:   k.Bytes(),
		nonce: n.Bytes(),
	}, nil
}

func persistKey(key *key, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	b := bytes.NewBuffer(nil)
	if _, err := b.Write(key.key); err != nil {
		return err
	}
	if _, err := b.Write(key.nonce); err != nil {
		return err
	}

	enc := hex.NewEncoder(f)
	if _, err := io.Copy(enc, b); err != nil {
		return err
	}
	if _, err := io.WriteString(f, "\n"); err != nil {
		return err
	}

	return nil
}

func getKey(path string) (*key, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	encodedKeyBytes := 2 * (keySizeBytes + nonceSizeBytes)

	b := &bytes.Buffer{}
	s, err := io.CopyN(b, f, int64(encodedKeyBytes))
	if err != nil {
		return nil, nil
	}
	if s != int64(encodedKeyBytes) {
		return nil, nil
	}

	k := make([]byte, keySizeBytes+nonceSizeBytes)
	if _, err := hex.Decode(k, b.Bytes()); err != nil {
		return nil, nil
	}

	return &key{
		key:   k[:keySizeBytes],
		nonce: k[keySizeBytes:],
	}, nil
}
