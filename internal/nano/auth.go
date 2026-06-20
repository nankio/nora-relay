package nano

// authDomain domain-separates enrollment signatures from block signatures, so a
// signed challenge can never be replayed as a transaction signature (block
// hashes are computed over a different preimage with the 0x06 preamble).
var authDomain = []byte("nora-auth-v1")

// AuthChallengeDigest is the 32-byte message an account signs to prove control
// of it during enrollment. It binds the signature to both the relay's nonce and
// the specific account, preventing cross-account or cross-protocol replay.
func AuthChallengeDigest(nonce []byte, account PublicKey) []byte {
	return blake2b256(authDomain, nonce, account[:])
}

// SignChallenge proves control of the account belonging to pk.
func SignChallenge(pk PrivateKey, nonce []byte) Signature {
	pub := pk.Public()
	return Sign(pk, AuthChallengeDigest(nonce, pub))
}

// VerifyChallenge checks a challenge signature for the given account.
func VerifyChallenge(account PublicKey, nonce []byte, sig Signature) bool {
	return Verify(account, AuthChallengeDigest(nonce, account), sig)
}

// PolicySyncKey derives a 32-byte symmetric key from an account's private key,
// used to end-to-end encrypt the policy (contacts/permissions) synced through
// the relay. Every device holding this account's seed derives the same key, so
// they can read each other's blobs while the relay only ever sees ciphertext.
func PolicySyncKey(pk PrivateKey) []byte {
	return blake2b256([]byte("nora-policy-sync-v1"), pk[:])
}
