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

	flag.BoolVar(&enc, "enc", false, "encrypt from stdin")
	flag.BoolVar(&dec, "dec", false, "dec from stdin")
	flag.StringVar(&keyFile, "key", "", "the path to the key")
	flag.Parse()

	switch {
	case enc:
		if keyFile == "" {
			if _, err := os.Stat("key.asc"); !os.IsNotExist(err) {
				log.Fatal("key path not provided")
			}

			log.Printf("key path not provided, using key.asc")
			keyFile = "key.asc"
		}
		if err := encrypt(os.Stdin, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error encrypting: %s", err)
		}

		return
	case dec:
		if keyFile == "" {
			log.Fatal("key path not provided")
		}
		if err := decrypt(os.Stdin, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error decrypting: %s", err)
		}

		return
	}

	flag.Usage()
}
