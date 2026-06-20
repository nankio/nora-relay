// Package nano implements the Nano (XNO) primitives required to run a
// non-custodial signer: key derivation, account encoding, state-block hashing,
// ed25519-blake2b signatures, and proof-of-work.
//
// Cryptographic primitives are delegated to audited libraries
// (golang.org/x/crypto/blake2b and filippo.io/edwards25519). We deliberately do
// not re-implement curve or hash arithmetic here — this code handles real funds.
package nano

import "golang.org/x/crypto/blake2b"

// blake2bSum hashes the concatenation of parts and returns a digest of size
// bytes (1..64). It panics only on programmer error (invalid size), never on
// input, so callers can use it inline.
func blake2bSum(size int, parts ...[]byte) []byte {
	h, err := blake2b.New(size, nil)
	if err != nil {
		panic("nano: invalid blake2b size: " + err.Error())
	}
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

// blake2b256 returns the 32-byte BLAKE2b digest of the concatenated parts.
func blake2b256(parts ...[]byte) []byte { return blake2bSum(32, parts...) }

// blake2b512 returns the 64-byte BLAKE2b digest of the concatenated parts.
func blake2b512(parts ...[]byte) []byte { return blake2bSum(64, parts...) }
