package nano

import (
	"errors"
	"strings"
)

// nanoAlphabet is Nano's custom base32 alphabet (RFC 4648 with a different,
// human-friendly ordering that omits visually ambiguous characters).
const nanoAlphabet = "13456789abcdefghijkmnopqrstuwxyz"

var nanoReverse = func() [128]int8 {
	var t [128]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(nanoAlphabet); i++ {
		t[nanoAlphabet[i]] = int8(i)
	}
	return t
}()

// PublicKey is a 32-byte Nano account public key.
type PublicKey [32]byte

// Address renders the public key as a canonical "nano_" account address,
// including the 8-character BLAKE2b checksum.
func (pk PublicKey) Address() string {
	account := encodeBase32(pk[:], 4) // 256 bits + 4 pad bits = 260 = 52 chars

	cs := blake2bSum(5, pk[:])
	reverseBytes(cs)
	checksum := encodeBase32(cs, 0) // 40 bits = 8 chars

	return "nano_" + account + checksum
}

// ParseAddress decodes a "nano_" or legacy "xrb_" address into a public key and
// verifies its checksum.
func ParseAddress(addr string) (PublicKey, error) {
	var pk PublicKey

	switch {
	case strings.HasPrefix(addr, "nano_"):
		addr = addr[5:]
	case strings.HasPrefix(addr, "xrb_"):
		addr = addr[4:]
	default:
		return pk, errors.New("nano: address must start with nano_ or xrb_")
	}
	if len(addr) != 60 {
		return pk, errors.New("nano: address has wrong length")
	}

	pub, err := decodeBase32(addr[:52], 4)
	if err != nil {
		return pk, err
	}
	if len(pub) != 32 {
		return pk, errors.New("nano: decoded public key has wrong length")
	}

	gotChecksum, err := decodeBase32(addr[52:], 0)
	if err != nil {
		return pk, err
	}
	reverseBytes(gotChecksum)

	want := blake2bSum(5, pub)
	if !bytesEqual(gotChecksum, want) {
		return pk, errors.New("nano: invalid address checksum")
	}

	copy(pk[:], pub)
	return pk, nil
}

// encodeBase32 encodes data into Nano base32, conceptually prefixing padBits
// zero bits so the total bit count is a multiple of 5.
func encodeBase32(data []byte, padBits int) string {
	total := padBits + len(data)*8
	var sb strings.Builder
	sb.Grow(total / 5)

	bitAt := func(i int) int {
		j := i - padBits
		if j < 0 {
			return 0
		}
		return int((data[j/8] >> (7 - uint(j%8))) & 1)
	}

	for i := 0; i < total; i += 5 {
		v := 0
		for k := 0; k < 5; k++ {
			v = (v << 1) | bitAt(i+k)
		}
		sb.WriteByte(nanoAlphabet[v])
	}
	return sb.String()
}

// decodeBase32 reverses encodeBase32, discarding the leading padBits.
func decodeBase32(s string, padBits int) ([]byte, error) {
	totalBits := len(s) * 5
	outBits := totalBits - padBits
	if outBits%8 != 0 {
		return nil, errors.New("nano: base32 length not byte-aligned")
	}
	out := make([]byte, outBits/8)

	bitIdx := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 128 || nanoReverse[c] < 0 {
			return nil, errors.New("nano: invalid base32 character")
		}
		v := int(nanoReverse[c])
		for k := 4; k >= 0; k-- {
			bit := (v >> uint(k)) & 1
			pos := bitIdx - padBits
			if pos >= 0 {
				out[pos/8] |= byte(bit) << (7 - uint(pos%8))
			}
			bitIdx++
		}
	}
	return out, nil
}

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
