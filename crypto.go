package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const (
	encKeySize = 32
	macKeySize = 32
	encIVSize  = 16
)

type message struct {
	IV     []byte
	MAC    []byte
	CTSize int64
}

type keys struct {
	EncKey []byte
	MACKey []byte
}

func encrypt(r io.Reader, w io.Writer, keyPath string) error {
	encKey, err := randBytes(rand.Reader, encKeySize)
	if err != nil {
		return err
	}
	macKey, err := randBytes(rand.Reader, macKeySize)
	if err != nil {
		return err
	}
	iv, err := randBytes(rand.Reader, encIVSize)
	if err != nil {
		return err
	}

	// Store the ciphertext here temporarily so that we can use
	// streams
	tmp, err := ioutil.TempFile("/tmp", "tulum-")
	if err != nil {
		return err
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	// MAC with HMAC-SHA-256
	mac := hmac.New(sha256.New, macKey)

	// Encrypt with AES-256-CTR
	ciph, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(ciph, iv)

	wr := cipher.StreamWriter{
		S: stream,
		W: io.MultiWriter(tmp, mac),
	}

	ctSize, err := io.Copy(wr, r)
	if err != nil {
		return err
	}
	if err := wr.Close(); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}

	msg := &message{
		IV:     iv,
		MAC:    mac.Sum(nil),
		CTSize: ctSize,
	}

	// Store msg's size as an int64 in w, followed by msg and the
	// ciphertext. This ensures that we can read out msg precisely
	// later.
	b := &bytes.Buffer{}
	if err := gob.NewEncoder(b).Encode(msg); err != nil {
		return err
	}
	bLen := int64(b.Len())
	if err := binary.Write(w, binary.LittleEndian, bLen); err != nil {
		return err
	}
	if _, err := io.Copy(w, b); err != nil {
		return err
	}
	if _, err := io.Copy(w, tmp); err != nil {
		return err
	}

	ks := &keys{
		EncKey: encKey,
		MACKey: macKey,
	}

	if err := persistKeys(ks, keyPath); err != nil {
		return err
	}

	return nil
}

func decrypt(r io.Reader, w io.Writer, keyPath string) error {
	ks, err := getKeys(keyPath)
	if err != nil {
		fmt.Println("hey")
		return err
	}
	tmp, err := ioutil.TempFile("/tmp", "tulum-")
	if err != nil {
		return err
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	mac := hmac.New(sha256.New, ks.MACKey)

	var msgSize int64
	if err := binary.Read(io.LimitReader(r, 8),
		binary.LittleEndian, &msgSize); err != nil {
		return err
	}

	var msg *message
	if err := gob.NewDecoder(io.LimitReader(r, msgSize)).Decode(&msg); err != nil {
		return err
	}
	if _, err := io.Copy(io.MultiWriter(tmp, mac), r); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}

	computedMac := mac.Sum(nil)
	if !hmac.Equal(computedMac, msg.MAC) {
		return errors.New("HMAC values do not match")
	}

	ciph, err := aes.NewCipher(ks.EncKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(ciph, msg.IV)

	rdr := cipher.StreamReader{
		S: stream,
		R: tmp,
	}
	if _, err := io.Copy(w, rdr); err != nil {
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

func persistKeys(ks *keys, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := base64.NewEncoder(base64.StdEncoding, f)

	if err := gob.NewEncoder(enc).Encode(ks); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if _, err := io.WriteString(f, "\n"); err != nil {
		return err
	}

	return nil
}

func getKeys(path string) (*keys, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := base64.NewDecoder(base64.StdEncoding, f)

	var ks *keys
	if err := gob.NewDecoder(dec).Decode(&ks); err != nil {
		return nil, err
	}

	return ks, nil
}
