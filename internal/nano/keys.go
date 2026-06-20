package nano

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// PrivateKey is a 32-byte Nano account private key (a single derived key, not a
// seed). Keep it secret; zero it when no longer needed.
type PrivateKey [32]byte

// Seed is a 32-byte wallet seed from which an unlimited number of account
// private keys are derived by index.
type Seed [32]byte

// NewSeed generates a cryptographically random wallet seed.
func NewSeed() (Seed, error) {
	var s Seed
	if _, err := rand.Read(s[:]); err != nil {
		return s, fmt.Errorf("nano: generating seed: %w", err)
	}
	return s, nil
}

// ParseSeed decodes a 64-character hex seed.
func ParseSeed(hexSeed string) (Seed, error) {
	var s Seed
	b, err := hex.DecodeString(hexSeed)
	if err != nil {
		return s, fmt.Errorf("nano: parsing seed: %w", err)
	}
	if len(b) != 32 {
		return s, errors.New("nano: seed must be 32 bytes (64 hex chars)")
	}
	copy(s[:], b)
	return s, nil
}

// Hex renders the seed as lowercase hex. Handle the result carefully.
func (s Seed) Hex() string { return hex.EncodeToString(s[:]) }

// DeriveKey derives the private key at the given index using Nano's standard
// scheme: blake2b256(seed || big-endian-uint32(index)).
func (s Seed) DeriveKey(index uint32) PrivateKey {
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], index)

	var pk PrivateKey
	copy(pk[:], blake2b256(s[:], idx[:]))
	return pk
}

// Public returns the ed25519-blake2b public key for this private key.
func (pk PrivateKey) Public() PublicKey {
	scalar, _ := expandedScalar(pk)
	A := new(edwards25519.Point).ScalarBaseMult(scalar)

	var pub PublicKey
	copy(pub[:], A.Bytes())
	return pub
}

// Address is a convenience wrapper returning the account address for this key.
func (pk PrivateKey) Address() string { return pk.Public().Address() }

// expandedScalar implements the ed25519 key expansion but with BLAKE2b-512
// (Nano's variant) instead of SHA-512. It returns the clamped secret scalar and
// the 32-byte prefix used for deterministic nonce generation.
func expandedScalar(pk PrivateKey) (*edwards25519.Scalar, []byte) {
	h := blake2b512(pk[:])

	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		// SetBytesWithClamping only errors on a wrong input length, which is
		// impossible here (h[:32] is always 32 bytes).
		panic("nano: scalar clamp failed: " + err.Error())
	}
	prefix := h[32:]
	return scalar, prefix
}
