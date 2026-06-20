package nano

import "testing"

func TestChallengeSignVerify(t *testing.T) {
	seed, _ := ParseSeed(zeroSeed)
	pk := seed.DeriveKey(0)
	account := pk.Public()
	nonce := []byte("a-random-32-byte-nonce-from-relay!!")

	sig := SignChallenge(pk, nonce)
	if !VerifyChallenge(account, nonce, sig) {
		t.Fatal("valid challenge signature failed verification")
	}

	// Different nonce must fail (replay protection).
	if VerifyChallenge(account, []byte("different-nonce"), sig) {
		t.Error("signature verified against a different nonce")
	}

	// A different account must fail (cross-account protection).
	other := seed.DeriveKey(1).Public()
	if VerifyChallenge(other, nonce, sig) {
		t.Error("signature verified for the wrong account")
	}
}

func TestChallengeIsNotABlockSignature(t *testing.T) {
	seed, _ := ParseSeed(zeroSeed)
	pk := seed.DeriveKey(0)
	nonce := make([]byte, 32)

	// The auth digest must differ from any 32-byte block hash signed directly,
	// so an enrollment signature cannot be reused as a transaction signature.
	authSig := SignChallenge(pk, nonce)
	if Verify(pk.Public(), nonce, authSig) {
		t.Error("auth signature also validates as a signature over the raw nonce")
	}
}
