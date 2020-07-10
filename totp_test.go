package gtotp

import (
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestTotp_At(t *testing.T) {
	totp := NewDefaultTotp("ninja@example.comHENNGECHALLENGE003")
	timestamp := 1594352095
	digitVal := totp.At(timestamp)
	assert.Equal(t, "0517636551", digitVal)
}
