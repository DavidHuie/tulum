package main

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"
)

func TestIntegration(t *testing.T) {
	defer gc()

	key, err := ioutil.TempFile("/tmp", "tulum-")
	if err != nil {
		t.Fatal(err)
	}
	key.Close()

	// We just need a name, but the file should not exist. We'll
	// create it elsewhere.
	os.Remove(key.Name())
	defer os.Remove(key.Name())

	plaintext, err := randBytes(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ptBuf := bytes.NewBuffer(plaintext)
	plaintext = ptBuf.Bytes()

	ct := &bytes.Buffer{}
	if err := encrypt(ptBuf, ct, rand.Reader, key.Name()); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct.Bytes(), plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	newPT := &bytes.Buffer{}
	if err := decrypt(ct, newPT, key.Name()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newPT.Bytes(), plaintext) {
		t.Fatal("decrypted plaintext should match original plaintext")
	}

	info, err := os.Stat(key.Name())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != keyAttributes {
		t.Fatal("invalid mode")
	}
}

func TestRandBytes(t *testing.T) {
	b1, err := randBytes(rand.Reader, 32)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := randBytes(rand.Reader, 32)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%x", b1)
	t.Logf("%x", b2)

	if bytes.Equal(b1, b2) {
		t.Fatal("rand bytes should not be equal")
	}
}

func TestDeriveKeys(t *testing.T) {
	s1 := []byte{1}
	s2 := []byte{2}

	ks1, err := deriveKeys(s1)
	if err != nil {
		t.Fatal(err)
	}
	ks2, err := deriveKeys(s2)
	if err != nil {
		t.Fatal(err)
	}

	if len(ks1.EncKey) != encKeySize {
		t.Fatal("invalid enc key size")
	}
	if len(ks1.MACKey) != hashSize {
		t.Fatal("invalid mac key size")
	}

	if bytes.Equal(ks1.EncKey, ks2.EncKey) {
		t.Fatal("keys should not match")
	}
	if bytes.Equal(ks1.MACKey, ks2.MACKey) {
		t.Fatal("keys should not match")
	}
}
