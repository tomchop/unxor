package unxor

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

// Xor performs a rolling-xor on cleartext with a key
func Xor(cleartext []byte, k []byte) []byte {
	xored := make([]byte, len(cleartext))
	for i, b := range cleartext {
		xored[i] = k[i%len(k)] ^ b
	}
	return xored
}

// XorMin performs a byte-to-byte xor with minimum length of both byte slices
func XorMin(cleartext []byte, k []byte) []byte {
	min := len(k)
	if min > len(cleartext) {
		min = len(cleartext)
	}
	xored := make([]byte, min)
	for i := 0; i < min; i++ {
		xored[i] = cleartext[i] ^ k[i]
	}
	return xored
}

// FindKey tries to find a key in a cyphertext based on known plaintext
func FindKey(crypt []byte, search []byte) ([]byte, error) {
	nSearch := make([]byte, len(search))
	nCrypt := make([]byte, len(crypt))
	copy(nSearch, search)
	copy(nCrypt, crypt)
	found := false
	i := 0

	for len(nSearch) > 0 && !found {
		i++
		nSearch = XorMin(nSearch, search[i:])
		nCrypt = XorMin(nCrypt, crypt[i:])
		if i%2 == 1 && len(nSearch) > 0 {
			keylen := (i/2 + 1)
			fmt.Printf("Trying keylen %d:", keylen)
			fmt.Printf("Searching for %q\n", nSearch)
			re := regexp.MustCompile(regexp.QuoteMeta(string(nSearch)))
			matches := re.FindAllIndex(nCrypt, -1)
			if matches != nil {
				for _, m := range matches {
					pos := m[0]
					fmt.Printf("Found normalized text at %d\n", pos)
					guess := Xor(crypt[pos:pos+len(search)], search)
					if keylen < len(search) {
						guess = guess[:keylen]
					}
					fmt.Printf("Guessing keystream: %q\n", guess)
					fmt.Printf("Shifting %d %% %d bytes: %d\n", pos, keylen, pos%keylen)
					guess = shiftSlice(guess, pos%keylen)
					decrypt := Xor(crypt, guess)
					if bytes.Index(decrypt, search) != -1 {
						fmt.Printf("Found good decryption for %q\n", guess)
						return guess, nil
					}
				}
			}

		}
	}
	return []byte{}, errors.New("unxor: Key not found")
}

func shiftSlice(slice []byte, n int) []byte {
	shifted := make([]byte, len(slice))
	copy(shifted, slice[len(slice)-n:])
	copy(shifted[n:], slice[:len(slice)-n])
	return shifted
}

// ReadFile Reads a file's bytes from disk
func ReadFile(fn string) []byte {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		panic(err)
	}
	return data
}

// DumpToFile dumps bytes to a file on disk
func DumpToFile(b []byte, fname string) int {
	f, _ := os.Create(fname)
	n, _ := f.Write(b)
	return n
}
