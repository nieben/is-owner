package eth

import (
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"io"
)

func Message() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func Verify(msg, sig []byte) (bool, error) {
	pubkey, err := secp256k1.RecoverPubkey(msg, sig)
	if err != nil {
		return false, err
	}

	signature := sig[:64] // Remove V(recovery id), [R || S] format 64 bytes

	return secp256k1.VerifySignature(pubkey, msg, signature), nil
}
