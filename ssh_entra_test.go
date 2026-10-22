package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestSSHCertAuthScheme(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	scheme, err := newSSHCertAuthScheme(pub)
	require.NoError(t, err)

	var jwk struct {
		Kty, N, E, Kid string
	}
	require.NoError(t, json.Unmarshal([]byte(scheme.jwk), &jwk))

	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "AQAB", jwk.E)

	modulus, err := base64.URLEncoding.DecodeString(jwk.N)
	require.NoError(t, err)
	assert.Equal(t, byte(0), modulus[0], "modulus should keep the SSH mpint sign byte like az ssh does")
	assert.Equal(t, 0, privateKey.N.Cmp(new(big.Int).SetBytes(modulus)))

	hash := sha256.Sum256([]byte(jwk.N + jwk.E))
	assert.Equal(t, hex.EncodeToString(hash[:]), jwk.Kid)
	assert.Equal(t, jwk.Kid, scheme.KeyID())
	assert.Equal(t, map[string]string{
		"token_type": "ssh-cert",
		"req_cnf":    scheme.jwk,
		"key_id":     jwk.Kid,
	}, scheme.TokenRequestParams())
}
