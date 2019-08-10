package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	unxor "github.com/tomchop/unxor/unxorlib"
)

func parseArgs() (*string, *string, *string) {
	fn := flag.String("f", "", "Filename to decrypt")
	g := flag.String("g", "", "Known plaintext (string)")
	gh := flag.String("gh", "", "Known plaintext (hex encoded)")
	flag.Parse()

	if *fn == "" {
		fmt.Println("You must specify a filename with the -f flag.")
		os.Exit(-1)
	}

	if *g != "" && *gh != "" {
		fmt.Println("-gh and -h are mutually exclusive.")
		os.Exit(-1)
	}

	if *g == "" && *gh == "" {
		fmt.Println("You must specify either -gh or -g.")
		os.Exit(-1)
	}

	return fn, g, gh
}

func main() {

	fn, g, gh := parseArgs()

	fmt.Printf("Reading from: %s\n", *fn)
	data := unxor.ReadFile(*fn)

	var knownPlaintext []byte
	if *gh != "" {
		fmt.Printf("Know plaintext (hex): %s\n", *gh)
		knownPlaintext, _ = hex.DecodeString(*gh)
	}
	if *g != "" {
		fmt.Printf("Know plaintext: %s\n", *g)
		knownPlaintext = []byte(*g)
	}

	key, err := unxor.FindKey(data, knownPlaintext)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	decrypted := unxor.Xor(data, key)

	dump := fmt.Sprintf("%s_decrypted", *fn)
	n := unxor.DumpToFile(decrypted, dump)
	fmt.Printf("Dumped %d decrypted bytes in %s\n", n, dump)
}
