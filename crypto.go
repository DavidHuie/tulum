package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	encKeySize = 32
	encIVSize  = 16

	keyAttributes = 0400

	base64LineLength = 76
)

var (
	hash     = sha3.New512
	hashSize = hash().Size()

	sourceKeySize = int64(hashSize)
)

type ctHeader struct {
	IV     []byte
	MAC    []byte
	CTSize int64
}

type keys struct {
	EncKey []byte
	MACKey []byte
}

func encrypt(r io.Reader, w io.Writer, rand io.Reader, keyPath string) error {
	defer gc()

	ks, err := genKeys(keyPath, rand)
	if err != nil {
		return err
	}
	iv, err := randBytes(rand, encIVSize)
	if err != nil {
		return err
	}

	tmp, err := getTempfile()
	if err != nil {
		return err
	}

	mac := hmac.New(hash, ks.MACKey)
	ciph, err := aes.NewCipher(ks.EncKey)
	if err != nil {
		return err
	}

	// Encrypt, calculating MAC on ciphertext.
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

	// Write header and ciphertext to writer.
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}
	header := &ctHeader{
		IV:     iv,
		MAC:    mac.Sum(nil),
		CTSize: ctSize,
	}
	if err := writeCiphertext(w, header, tmp); err != nil {
		return err
	}

	return nil
}

func writeCiphertext(dest io.Writer, head *ctHeader, ct io.Reader) error {
	// The encoded cipher text has the following binary format:
	//
	// 8 bytes - int64 size of header (s)
	// s bytes - gob-encoded ctHeader (contains CTSize field)
	// CTSize bytes - raw ciphertext data

	b := &bytes.Buffer{}
	if err := gob.NewEncoder(b).Encode(head); err != nil {
		return err
	}

	// Write the size of the header.
	headerSize := int64(b.Len())
	if err := binary.Write(dest, binary.LittleEndian, headerSize); err != nil {
		return err
	}

	// Write the header.
	if _, err := io.Copy(dest, b); err != nil {
		return err
	}

	// Write the ciphertext.
	if _, err := io.Copy(dest, ct); err != nil {
		return err
	}

	return nil
}

func readCiphertextHeader(r io.Reader) (*ctHeader, error) {
	var headerSize int64
	if err := binary.Read(io.LimitReader(r, 8),
		binary.LittleEndian, &headerSize); err != nil {
		return nil, err
	}

	var header *ctHeader
	if err := gob.NewDecoder(io.LimitReader(r, headerSize)).Decode(&header); err != nil {
		return nil, err
	}

	return header, nil
}

func decrypt(r io.Reader, w io.Writer, keyPath string) error {
	defer gc()

	ks, err := getKeys(keyPath)
	if err != nil {
		return err
	}

	tmp, err := getTempfile()
	if err != nil {
		return err
	}

	header, err := readCiphertextHeader(r)
	if err != nil {
		return err
	}

	// Check MAC.
	mac := hmac.New(hash, ks.MACKey)
	if _, err := io.Copy(io.MultiWriter(tmp, mac), r); err != nil {
		return err
	}
	computedMac := mac.Sum(nil)
	if !hmac.Equal(computedMac, header.MAC) {
		return errors.New("HMAC values do not match")
	}

	// Decrypt
	ciph, err := aes.NewCipher(ks.EncKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(ciph, header.IV)
	if _, err := tmp.Seek(0, 0); err != nil {
		return err
	}
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
	source := make([]byte, hashSize)
	if _, err := io.ReadFull(r, source); err != nil {
		return nil, err
	}

	data := make([]byte, n)
	hkdf := hkdf.New(hash, source, nil, nil)
	if _, err := io.ReadFull(hkdf, data); err != nil {
		return nil, err
	}

	return data, nil
}

func deriveKeys(source []byte) (*keys, error) {
	derived := make([]byte, encKeySize+hashSize)
	hkdf := hkdf.New(hash, source, nil, nil)
	if _, err := io.ReadFull(hkdf, derived); err != nil {
		return nil, err
	}

	encKey := derived[:encKeySize]
	macKey := derived[encKeySize : encKeySize+hashSize]

	ks := &keys{
		EncKey: encKey,
		MACKey: macKey,
	}

	return ks, nil
}

func genKeys(path string, rand io.Reader) (*keys, error) {
	sourceKey, err := randBytes(rand, sourceKeySize)
	if err != nil {
		return nil, err
	}

	ks, err := deriveKeys(sourceKey)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, keyAttributes)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b := &bytes.Buffer{}
	enc := base64.NewEncoder(base64.StdEncoding, b)
	if _, err := enc.Write(sourceKey); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}

	// Add line wrapping to the key so that it matches the output
	// by `base64`.
	line := make([]byte, base64LineLength)
	for {
		n, err := b.Read(line)
		if n > 0 {
			l := fmt.Sprintf("%s\n", string(line[:n]))
			if _, err := f.WriteString(l); err != nil {
				return nil, err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
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
	sourceKey := &bytes.Buffer{}
	if _, err := io.Copy(sourceKey, dec); err != nil {
		return nil, err
	}

	ks, err := deriveKeys(sourceKey.Bytes())
	if err != nil {
		return nil, err
	}

	return ks, err
}

func getTempfile() (*os.File, error) {
	gcLock.Lock()
	defer gcLock.Unlock()

	tmp, err := ioutil.TempFile("/tmp", "tulum-")
	if err != nil {
		return tmp, err
	}

	toGC = append(toGC, func() {
		tmp.Close()
		os.Remove(tmp.Name())
	})

	return tmp, nil
}

func gc() {
	gcLock.Lock()
	defer gcLock.Unlock()

	for _, c := range toGC {
		c()
	}

	toGC = []func(){}
}

func init() {
	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		<-sigs
		gc()
	}()
}
