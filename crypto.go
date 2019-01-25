package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
)

const (
	keySizeBytes   = 16
	nonceSizeBytes = 12
)

type message struct {
	CT    []byte
	Nonce []byte
}

func encrypt(r io.Reader, w io.Writer, keyPath string) error {
	key, err := randBytes(rand.Reader, keySizeBytes)
	if err != nil {
		return err
	}
	nonce, err := randBytes(rand.Reader, nonceSizeBytes)
	if err != nil {
		return err
	}

	ciph, err := aes.NewCipher(key)
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

	ct := aead.Seal(nil, nonce, pt, nil)

	msg := &message{
		CT:    ct,
		Nonce: nonce,
	}

	if err := gob.NewEncoder(w).Encode(msg); err != nil {
		return err
	}
	if err := persistKey(key, keyPath); err != nil {
		return err
	}

	return nil
}

func decrypt(r io.Reader, w io.Writer, keyPath string) error {
	key, err := getKey(keyPath)
	if err != nil {
		return err
	}

	var msg *message
	if err := gob.NewDecoder(r).Decode(&msg); err != nil {
		return err
	}

	ciph, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(ciph)
	if err != nil {
		return err
	}

	pt, err := aead.Open(nil, msg.Nonce, msg.CT, nil)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, bytes.NewBuffer(pt)); err != nil {
		return err
	}

	return nil
}

func randBytes(r io.Reader, n int64) ([]byte, error) {
	b := &bytes.Buffer{}
	if _, err := io.CopyN(b, r, n); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func persistKey(key []byte, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	b := bytes.NewBuffer(nil)
	if _, err := b.Write(key); err != nil {
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

func getKey(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	encodedKeyBytes := 2 * keySizeBytes

	b := &bytes.Buffer{}
	s, err := io.CopyN(b, f, int64(encodedKeyBytes))
	if err != nil {
		return nil, nil
	}
	if s != int64(encodedKeyBytes) {
		return nil, nil
	}

	k := make([]byte, keySizeBytes)
	if _, err := hex.Decode(k, b.Bytes()); err != nil {
		return nil, nil
	}

	return k, nil
}
