package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
)

var (
	enc     bool
	dec     bool
	keyFile string
	toGC    []func()
	gcLock  = &sync.Mutex{}
)

func main() {
	log.SetOutput(os.Stderr)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Tulum is a simple, fast, zero-configuration file encryption tool.\n")
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		fmt.Fprintln(flag.CommandLine.Output(), "  tulum [flags] [file]")
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}

	flag.BoolVar(&enc, "enc", true, "encrypt from file argument or stdin, writing output to stdout")
	flag.BoolVar(&dec, "dec", false, "decrypt from file argument or stdin, writing output to stdout")
	flag.StringVar(&keyFile, "key", "key.asc", "the path to the key")
	flag.Parse()

	// Only one of enc or dec should be true, but enc is always
	// true by default.
	if dec {
		enc = false
	}

	// Use a file instead of stdin if the user specifies one.
	reader := os.Stdin
	if file := flag.Arg(0); file != "" {
		f, err := os.Open(file)
		if err != nil {
			log.Fatalf("Error opening file: %s", err)
		}
		defer f.Close()
		reader = f
	}

	switch {
	case enc:
		if err := encrypt(reader,
			os.Stdout, rand.Reader, keyFile); err != nil {
			log.Fatalf("Error encrypting: %s", err)
		}
	case dec:
		if err := decrypt(reader, os.Stdout, keyFile); err != nil {
			log.Fatalf("Error decrypting: %s", err)
		}
	default:
		flag.Usage()
	}

	gc()
}
