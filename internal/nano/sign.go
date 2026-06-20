package nano

import "filippo.io/edwards25519"

// Signature is a 64-byte ed25519-blake2b signature over a 32-byte block hash.
type Signature [64]byte

// Sign produces an ed25519-blake2b signature of msg (normally a block hash).
//
// This is the standard ed25519 signing algorithm with BLAKE2b-512 substituted
// for SHA-512 everywhere a hash is used — exactly the variant Nano consensus
// requires.
func Sign(pk PrivateKey, msg []byte) Signature {
	a, prefix := expandedScalar(pk)
	A := new(edwards25519.Point).ScalarBaseMult(a)
	pub := A.Bytes()

	// r = H(prefix || msg)  (reduced mod L)
	r, err := edwards25519.NewScalar().SetUniformBytes(blake2b512(prefix, msg))
	if err != nil {
		panic("nano: r reduction failed: " + err.Error())
	}
	R := new(edwards25519.Point).ScalarBaseMult(r)
	Rb := R.Bytes()

	// k = H(R || A || msg)  (reduced mod L)
	k, err := edwards25519.NewScalar().SetUniformBytes(blake2b512(Rb, pub, msg))
	if err != nil {
		panic("nano: k reduction failed: " + err.Error())
	}

	// S = r + k*a  (mod L)
	S := edwards25519.NewScalar().MultiplyAdd(k, a, r)

	var sig Signature
	copy(sig[:32], Rb)
	copy(sig[32:], S.Bytes())
	return sig
}

// Verify reports whether sig is a valid ed25519-blake2b signature of msg under
// the given public key. It rejects non-canonical encodings.
func Verify(pub PublicKey, msg []byte, sig Signature) bool {
	A, err := new(edwards25519.Point).SetBytes(pub[:])
	if err != nil {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}
	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	k, err := edwards25519.NewScalar().SetUniformBytes(blake2b512(sig[:32], pub[:], msg))
	if err != nil {
		return false
	}

	// Check that [S]B == R + [k]A.
	sB := new(edwards25519.Point).ScalarBaseMult(S)
	kA := new(edwards25519.Point).ScalarMult(k, A)
	expected := new(edwards25519.Point).Add(R, kA)

	return sB.Equal(expected) == 1
}
