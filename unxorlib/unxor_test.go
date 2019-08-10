package unxor

import (
	"bytes"
	"fmt"
	"testing"
)

func TestFindKey(t *testing.T) {
	cases := []struct {
		inFile, knownPt string
		key             []byte
	}{
		{"test_data/xored_file_ABCDEF", "readymade", []byte{0xAB, 0xCD, 0xEF}},
		{"test_data/xored_file_ABCDEF", "messenger", []byte{0xAB, 0xCD, 0xEF}},
		{"test_data/xored_file_ABCDEF01", " messenger", []byte{0xAB, 0xCD, 0xEF, 0x01}},
		{"test_data/xored_file_ABCDEF0102", "messenger ", []byte{0xAB, 0xCD, 0xEF, 0x01, 0x02}},
		{"test_data/xored_file_ABCDEF1234567890", "sartorial messenger", []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90}},
		{"test_data/xored_file_ABCDEF1234567890", "WILLNEVERFINDTHIS", []byte{}},
	}
	for _, c := range cases {
		data := ReadFile(c.inFile)
		guess, err := FindKey(data, []byte(c.knownPt))
		if !bytes.Equal(guess, c.key) {
			t.Errorf("FindKey failed: found %q, wanted %q", guess, c.key)
		}
		if c.knownPt == "WILLNEVERFINDTHIS" {
			if fmt.Sprintf("%s", err) != "unxor: Key not found" {
				t.Errorf("Error message not generated: %s", err)
			}
		}
	}

}

func TestShift(t *testing.T) {
	cases := []struct {
		n        int
		in, want []byte
	}{
		{3, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{6, 7, 8, 1, 2, 3, 4, 5}},
		{0, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{8, []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}
	for _, c := range cases {
		shifted := shiftSlice(c.in, c.n)
		if !bytes.Equal(c.want, shifted) {
			t.Errorf("shiftSlice(%q, %d) == %q, want %q", c.in, c.n, shifted, c.want)
		}
	}
}

func TestXor(t *testing.T) {
	cases := []struct {
		k, in, want []byte
	}{
		{[]byte{0x20}, []byte("helloworld"), []byte("HELLOWORLD")},
		{[]byte{0x20, 0x20, 0x20}, []byte("helloworld"), []byte("HELLOWORLD")},
		{[]byte{0x20, 0x00}, []byte("helloworld"), []byte("HeLlOwOrLd")},
		{[]byte{0x20, 0x00, 0x20, 0x00}, []byte("helloworld"), []byte("HeLlOwOrLd")},
	}
	for _, c := range cases {
		got := Xor(c.in, c.k)
		if !bytes.Equal(got, c.want) {
			t.Errorf("Xor(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}
