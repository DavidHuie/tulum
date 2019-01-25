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

	flag.BoolVar(&enc, "enc", false, "encrypt from stdin, writing output to stdout")
	flag.BoolVar(&dec, "dec", false, "decrypt from stdin, writing output to stdout")
	flag.StringVar(&keyFile, "key", "", "the path to the key")
	flag.Parse()

	switch {
	case enc:
		if keyFile == "" {
			keyFile = "key.asc"
		}
		if err := encrypt(os.Stdin, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error encrypting: %s", err)
		}
	case dec:
		if keyFile == "" {
			keyFile = "key.asc"
		}
		if err := decrypt(os.Stdin, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error decrypting: %s", err)
		}
	default:
		flag.Usage()
	}
}
