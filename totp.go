package gtotp

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
	"math"
	"time"
)

type Totp struct {
	secret string           // the K, also the shared secret
	cfg    TotpAlgorithmCfg // totp algorithm config parameters
	hasher *Hasher          // Hmac hash function
}

type TotpAlgorithmCfg struct {
	rtnDigitSize int // the return digit value length
	t0           int // the T0, default is 0
	timeStep     int // the X, default is 30
}

type Hasher struct {
	HashName string           // hash digit name
	Digest   func() hash.Hash // hash function, default is sha512
}

// NewDefaultTotp return Totp reference using default config parameters.
func NewDefaultTotp(sharedSecret string) *Totp {
	return &Totp{
		secret: sharedSecret,
		cfg: TotpAlgorithmCfg{
			rtnDigitSize: 10,
			t0:           0,
			timeStep:     30,
		},
		hasher: &Hasher{
			HashName: "sha512",
			Digest:   sha512.New,
		},
	}
}

// Now return the digit value by current timestamp.
func (t *Totp) Now() string {
	return t.At(int(time.Now().Unix()))
}

// At return the gigit value with the timestamp parameter.
func (t *Totp) At(timestamp int) string {
	currentSteps := t.steps(timestamp)
	byteSecret := []byte(t.secret)
	secretHash := hmac.New(t.hasher.Digest, byteSecret)
	bSteps := Itob(currentSteps)
	secretHash.Write(bSteps)
	hmacHash := secretHash.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)

	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(t.cfg.rtnDigitSize))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", t.cfg.rtnDigitSize), code)
}

// calculate the steps of timestamp.
func (t *Totp) steps(timestamp int) int {
	return int((timestamp - t.cfg.t0) / t.cfg.timeStep)
}

// integer to byte array
func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}
