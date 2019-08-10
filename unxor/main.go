package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	unxor "github.com/tomchop/unxor/unxorlib"
)

func main() {
	fname := flag.String("f", "", "Filename to decrypt")
	guess := flag.String("g", "", "Known plaintext (string)")
	guessHex := flag.String("h", "", "Known plaintext (hex encoded)")
	flag.Parse()

	if *fname == "" {
		fmt.Printf("You must specify a filename with the -f flag.")
		os.Exit(-1)
	}

	if *guess != "" && *guessHex != "" {
		fmt.Printf("-g and -h are mutually exclusive.")
		os.Exit(-1)
	}

	var knownPlaintext []byte
	if *guessHex != "" {
		fmt.Printf("Know plaintext (hex): %s\n", *guessHex)
		knownPlaintext, _ = hex.DecodeString(*guessHex)
	}
	if *guess != "" {
		fmt.Printf("Know plaintext: %s\n", *guess)
		knownPlaintext = []byte(*guess)
	}

	fmt.Printf("Reading from: %s\n", *fname)
	data := unxor.ReadFile(*fname)
	key := unxor.FindKey(data, knownPlaintext)
	decrypted := unxor.Xor(data, key)
	unxor.DumpToFile(decrypted, fmt.Sprintf("%s_decrypted", *fname))
}
