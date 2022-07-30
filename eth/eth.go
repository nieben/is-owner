package eth

import (
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"io"
	"strings"
)

func Message() ([]byte, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func Verify(address string, msg, sig []byte) (bool, error) {
	pubkey, err := secp256k1.RecoverPubkey(msg, sig)
	if err != nil {
		return false, err
	}

	pk, err := crypto.UnmarshalPubkey(pubkey)
	if err != nil {
		return false, err
	}

	if strings.ToLower(crypto.PubkeyToAddress(*pk).Hex()) != strings.ToLower(address) {
		return false, nil
	}

	signature := sig[:64] // Remove V(recovery id), [R || S] format 64 bytes

	return secp256k1.VerifySignature(pubkey, msg, signature), nil
}
