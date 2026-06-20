package nano

import (
	"errors"
	"math/big"
)

// RawPerNano is the number of raw units in one Nano (XNO): 10^30.
var RawPerNano = func() *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
}()

// ParseNanoAmount converts a decimal Nano amount string (e.g. "1.5") to raw.
func ParseNanoAmount(s string) (*big.Int, error) {
	rat, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("nano: invalid decimal amount")
	}
	rat.Mul(rat, new(big.Rat).SetInt(RawPerNano))
	if !rat.IsInt() {
		return nil, errors.New("nano: amount has more precision than 1 raw")
	}
	if rat.Sign() < 0 {
		return nil, errors.New("nano: amount must not be negative")
	}
	return rat.Num(), nil
}

// FormatNanoAmount renders a raw amount as a decimal Nano string.
func FormatNanoAmount(raw *big.Int) string {
	if raw == nil {
		return "0"
	}
	return new(big.Rat).SetFrac(raw, RawPerNano).FloatString(30)
}
