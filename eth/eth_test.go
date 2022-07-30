package eth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"testing"
)

func init() {

}

func TestMessage(t *testing.T) {
	msg, err := Message()
	if err != nil {
		t.Errorf("get message err: %s", err.Error())
		return
	}

	if len(msg) != 32 {
		t.Errorf("message length mismatch: want: 32 have: %d", len(msg))
	} else {
		t.Logf("TestMessage success: %s", string(msg))
	}
}

func TestVerify(t *testing.T) {
	pubkey, seckey := generateKeyPair()
	msg, err := Message()
	if err != nil {
		t.Errorf("gen message error: %s", err)
	}
	sig, err := secp256k1.Sign(msg, seckey)
	if err != nil {
		t.Errorf("signature error: %s", err)
	}

	compactSigCheck(t, sig)
	if len(pubkey) != 65 {
		t.Errorf("pubkey length mismatch: want: 65 have: %d", len(pubkey))
	}
	if len(seckey) != 32 {
		t.Errorf("seckey length mismatch: want: 32 have: %d", len(seckey))
	}
	if len(sig) != 65 {
		t.Errorf("sig length mismatch: want: 65 have: %d", len(sig))
	}
	recid := int(sig[64])
	if recid > 4 || recid < 0 {
		t.Errorf("sig recid mismatch: want: within 0 to 4 have: %d", int(sig[64]))
	}

	rt, err := Verify(msg, sig)
	if err != nil {
		t.Errorf("signature verify err: %s, msg: %v, sig: %v",
			err.Error(), msg, sig)
		return
	}
	if !rt {
		t.Errorf("signature verify failed, msg: %v, sig: %v",
			msg, sig)
	} else {
		t.Logf("TestVerify success with pubkey: %v", pubkey)
	}
}

func generateKeyPair() (pubkey, privkey []byte) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)

	if err != nil {
		panic(err)
	}

	//address := crypto2.PubkeyToAddress(key.PublicKey).String()
	//fmt.Println(address)
	pubkey = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey
}

// tests for malleability
// highest bit of signature ECDSA s value must be 0, in the 33th byte
func compactSigCheck(t *testing.T, sig []byte) {
	var b = int(sig[32])
	if b < 0 {
		t.Errorf("highest bit is negative: %d", b)
	}
	if ((b >> 7) == 1) != ((b & 0x80) == 0x80) {
		t.Errorf("highest bit: %d bit >> 7: %d", b, b>>7)
	}
	if (b & 0x80) == 0x80 {
		t.Errorf("highest bit: %d bit & 0x80: %d", b, b&0x80)
	}
}
