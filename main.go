package main

import (
	"flag"
	"log"
	"os"
)

var (
	enc     bool
	dec     bool
	keyFile string
)

func main() {
	log.SetOutput(os.Stderr)

	flag.BoolVar(&enc, "enc", true, "encrypt from stdin, writing output to stdout")
	flag.BoolVar(&dec, "dec", false, "decrypt from stdin, writing output to stdout")
	flag.StringVar(&keyFile, "key", "key.asc", "the path to the key")
	flag.Parse()

	// Only one of enc or dec should be true, but enc is always
	// true by default.
	if dec {
		enc = false
	}

	switch {
	case enc:
		if err := encrypt(os.Stdin, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error encrypting: %s", err)
		}
	case dec:
		if err := decrypt(os.Stdin, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error decrypting: %s", err)
		}
	default:
		flag.Usage()
	}
}
