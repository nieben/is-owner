package eth

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"testing"
)

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
	msg, err := Message()
	if err != nil {
		t.Errorf("gen message error: %s", err)
	}

	seckey, _ := crypto.LoadECDSA("samplePrvKey")

	sig, err := secp256k1.Sign(msg, crypto.FromECDSA(seckey))
	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}

	address := crypto.PubkeyToAddress(seckey.PublicKey).Hex()

	rt, err := Verify(address, msg, sig)
	if err != nil {
		t.Errorf("signature verify err: %s, address: %s, msg: %v, sig: %v",
			err.Error(), address, msg, sig)
		return
	}
	if !rt {
		t.Errorf("TestVerify failed, address: %s, msg: %v, sig: %v", address, msg, sig)
	} else {
		t.Logf("TestVerify success with address: %v", address)
	}
}

func TestVerifyInvalidAddress(t *testing.T) {
	msg, err := Message()
	if err != nil {
		t.Errorf("gen message error: %s", err)
		return
	}

	seckey, _ := crypto.LoadECDSA("samplePrvKey")

	sig, err := secp256k1.Sign(msg, crypto.FromECDSA(seckey))
	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}

	invalidAddress := "0x0000000000000000000000000000000000000000"

	rt, err := Verify(invalidAddress, msg, sig)
	if err != nil {
		t.Errorf("signature verify err: %s, address: %s, msg: %v, sig: %v",
			err.Error(), invalidAddress, msg, sig)
		return
	}
	if !rt {
		t.Logf("TestVerifyInvalidAddress success with expceted result false: %v, address: %s", rt, invalidAddress)
	} else {
		t.Errorf("signature verify failed, address: %s, msg: %v, sig: %v",
			invalidAddress, msg, sig)
	}
}

func TestVerifyInvalidSign(t *testing.T) {
	msg, err := Message()
	if err != nil {
		t.Errorf("gen message error: %s", err)
		return
	}

	seckey, _ := crypto.LoadECDSA("samplePrvKey")

	badSig, err := secp256k1.Sign(msg, crypto.FromECDSA(seckey))
	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}
	badSig[0] = 9 // change sig to invalid

	address := crypto.PubkeyToAddress(seckey.PublicKey).Hex()

	rt, err := Verify(address, msg, badSig)
	if err != nil {
		t.Errorf("signature verify err: %s, address: %s, msg: %v, sig: %v",
			err.Error(), address, msg, badSig)
		return
	}
	if !rt {
		t.Logf("TestVerifyInvalidSign success with expceted result false: %v, address: %s, randomSig: %v",
			rt, address, badSig)
	} else {
		t.Errorf("TestVerifyInvalidSign failed, address: %s, msg: %v, sig: %v",
			address, msg, badSig)
	}
}

func TestVerifyWithRandomPrvKey(t *testing.T) {
	msg, err := Message()
	if err != nil {
		t.Errorf("gen message error: %s", err)
		return
	}

	// random generated private key
	seckey, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("GenerateKey error: %s", err)
		return
	}

	sig, err := secp256k1.Sign(msg, crypto.FromECDSA(seckey))
	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}

	address := crypto.PubkeyToAddress(seckey.PublicKey).Hex()

	rt, err := Verify(address, msg, sig)
	if err != nil {
		t.Errorf("signature verify err: %s, address: %s, msg: %v, sig: %v",
			err.Error(), address, msg, sig)
		return
	}
	if !rt {
		t.Errorf("TestVerifyWithRandomPrvKey failed, address: %s, msg: %v, sig: %v",
			address, msg, sig)
	} else {
		t.Logf("TestVerifyWithRandomPrvKey success with random address: %v", address)
	}
}
