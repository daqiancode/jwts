package jwts_test

import (
	"testing"

	"github.com/daqiancode/jwts"
	"github.com/stretchr/testify/assert"
)

func TestGenerateEdDSAKeyPair(t *testing.T) {
	pub, pri, err := jwts.GenerateEdDSAKeyPair()
	assert.Nil(t, err)
	assert.True(t, len(pub) > 0)
	assert.True(t, len(pri) > 0)
}
