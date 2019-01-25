package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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

type ctPayload struct {
	IV     []byte
	MAC    []byte
	CTSize int64
}

type keys struct {
	EncKey []byte
	MACKey []byte
}

func encrypt(r io.Reader, w io.Writer, rand io.Reader, keyPath string) error {
	ks, err := genKeys(keyPath, rand)
	if err != nil {
		return nil
	}

	iv, err := randBytes(rand, encIVSize)
	if err != nil {
		return err
	}

	// Store the ciphertext here temporarily so that we can MAC it
	// before sending it.
	tmp, err := ioutil.TempFile("/tmp", "tulum-")
	if err != nil {
		return err
	}
	defer tmp.Close()
	defer os.Remove(tmp.Name())

	// MAC with HMAC-SHA-256
	mac := hmac.New(sha256.New, ks.MACKey)

	// Encrypt with AES-256-CTR
	ciph, err := aes.NewCipher(ks.EncKey)
	if err != nil {
		return err
	}

	aesWriter := cipher.StreamWriter{
		S: cipher.NewCTR(ciph, iv),
		W: io.MultiWriter(tmp, mac),
	}

	ctSize, err := io.Copy(aesWriter, r)
	if err != nil {
		return err
	}
	if err := aesWriter.Close(); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}

	ct := &ctPayload{
		IV:     iv,
		MAC:    mac.Sum(nil),
		CTSize: ctSize,
	}

	// Store ct's size as an int64 in w, followed by ct and the
	// ciphertext. This ensures that we can read out ct precisely
	// later.
	b := &bytes.Buffer{}
	if err := gob.NewEncoder(b).Encode(ct); err != nil {
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

	var ctSize int64
	if err := binary.Read(io.LimitReader(r, 8),
		binary.LittleEndian, &ctSize); err != nil {
		return err
	}

	var ct *ctPayload
	if err := gob.NewDecoder(io.LimitReader(r, ctSize)).Decode(&ct); err != nil {
		return err
	}
	if _, err := io.Copy(io.MultiWriter(tmp, mac), r); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}

	computedMac := mac.Sum(nil)
	if !hmac.Equal(computedMac, ct.MAC) {
		return errors.New("HMAC values do not match")
	}

	ciph, err := aes.NewCipher(ks.EncKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(ciph, ct.IV)

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

func genKeys(path string, rand io.Reader) (*keys, error) {
	encKey, err := randBytes(rand, encKeySize)
	if err != nil {
		return nil, err
	}
	macKey, err := randBytes(rand, macKeySize)
	if err != nil {
		return nil, err
	}

	ks := &keys{
		EncKey: encKey,
		MACKey: macKey,
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	enc := base64.NewEncoder(base64.StdEncoding, f)

	if err := gob.NewEncoder(enc).Encode(ks); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(f, "\n"); err != nil {
		return nil, err
	}

	return ks, nil
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
