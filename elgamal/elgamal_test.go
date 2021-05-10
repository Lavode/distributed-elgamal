package elgamal

import (
	"bytes"
	"github.com/lavode/secret-sharing/gf"
	"github.com/lavode/secret-sharing/secretshare"
	"math/big"
	"testing"
)

func TestPublicKeyField(t *testing.T) {
	pk := PublicKey{
		SchnorrGroup: SchnorrGroup{
			P: big.NewInt(23),
			Q: big.NewInt(11),
			G: big.NewInt(4),
		},
		Y: big.NewInt(8),
	}

	field, err := pk.Field()
	if err != nil {
		t.Fatalf("Error generating field: %v", err)
	}

	if field.P.Cmp(pk.P) != 0 {
		t.Errorf("Expected GF(%d); got GF(%d)", pk.P, field.P)
	}
}

func TestKeyGen(t *testing.T) {
	pub, priv, shares, err := KeyGen(20, 10, 3, 5)
	if err != nil {
		t.Fatalf("Error in KeyGen: %v", err)
	}

	// We won't repeat all tests done in the tests of
	// GenerateSchnorrGroup(), just some sanity checks.
	if !pub.P.ProbablyPrime(32) {
		t.Errorf("Expected p to be prime; got %d", pub.P)
	}

	if !pub.Q.ProbablyPrime(32) {
		t.Errorf("Expected q to be prime; got %d", pub.Q)
	}

	// Generator must be a group member, that is g^q \equiv 1 mod p
	var elem = &big.Int{}
	elem.Exp(pub.G, pub.Q, pub.P)
	if elem.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected g^q mod p = 1; got %d", elem)
	}

	if len(shares) != 5 {
		t.Errorf("Expected 5 shares; got %d", len(shares))
	}

	field, err := gf.NewGF(pub.Q)
	if err != nil {
		t.Fatalf("Error generating field: %v", err)
	}

	recoverShares := []secretshare.Share{
		{ID: shares[0].ID, Value: shares[0].Value},
		{ID: shares[2].ID, Value: shares[2].Value},
		{ID: shares[3].ID, Value: shares[3].Value},
	}
	recoveredSecret, err := secretshare.TOutOfNRecover(recoverShares, field)
	if err != nil {
		t.Fatalf("Error recovering secret: %v", err)
	}
	if recoveredSecret.Cmp(priv.X) != 0 {
		t.Errorf("Expected recovered secret = %d; got %d", priv.X, recoveredSecret)
	}
}

func TestEnc(t *testing.T) {
	pub := PublicKey{
		SchnorrGroup: SchnorrGroup{
			P: big.NewInt(23),
			Q: big.NewInt(11),
			G: big.NewInt(4),
		},
		Y: big.NewInt(8),
	}

	msg := []byte("Hello world")
	ctxt, err := Enc(pub, msg)
	if err != nil {
		t.Fatalf("Enc returned error: %v", err)
	}
	if len(ctxt.C) != 64 {
		t.Errorf("Expected ciphertext of 64 bytes; got %d", len(ctxt.C))
	}
	// TODO test that decryption returns actual message
	// TODO test that only correct-length message is allowed

	msg = make([]byte, 65)
	_, err = Enc(pub, msg)
	if err == nil {
		t.Errorf("Expected error if message exceeds 64 bytes; got none")
	}
}

func TestDec(t *testing.T) {
	pub := PublicKey{
		SchnorrGroup: SchnorrGroup{
			P: big.NewInt(23),
			Q: big.NewInt(11),
			G: big.NewInt(4),
		},
		Y: big.NewInt(16), // x = 2
	}

	// Ciphertext encoding of message 'Hello world' padded to 64 bytes
	// Only the `R` component is relevant for this test
	ctxt := Ciphertext{
		R: big.NewInt(3), // r = 4
		C: []byte{0xBA, 0x1E, 0x37, 0x94, 0xBC, 0x7E, 0xD5, 0xD4, 0xC9, 0x0, 0x6B, 0x9F, 0xEF, 0x89, 0xD8, 0x83, 0x41, 0x5B, 0x5A, 0xDB, 0xD6, 0xA8, 0x40, 0x30, 0xCB, 0x1F, 0x35, 0xE6, 0xA6, 0xC0, 0x26, 0xE6, 0x5C, 0x60, 0xFB, 0x99, 0xF5, 0x62, 0xF7, 0xEB, 0x9F, 0x77, 0xF3, 0xDE, 0xC5, 0x0, 0x14, 0x73, 0x44, 0x1D, 0x2C, 0x55, 0x86, 0xB5, 0x4D, 0x9B, 0x99, 0x9C, 0xF4, 0xBD, 0x79, 0xE, 0x4C, 0x56},
	}

	// Three keyshares out of a 3-out-of-5 secret share of x and their
	// corresponding (expected) decryption shares.
	k1 := PrivateKeyShare(secretshare.Share{ID: 1, Value: big.NewInt(4)})
	k3 := PrivateKeyShare(secretshare.Share{ID: 3, Value: big.NewInt(14)})
	k4 := PrivateKeyShare(secretshare.Share{ID: 4, Value: big.NewInt(22)})

	ed1 := DecryptionShare(secretshare.Share{ID: 1, Value: big.NewInt(12)})
	ed3 := DecryptionShare(secretshare.Share{ID: 3, Value: big.NewInt(4)})
	ed4 := DecryptionShare(secretshare.Share{ID: 4, Value: big.NewInt(1)})

	d1, err := Dec(pub, k1, ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}
	if d1.ID != ed1.ID || d1.Value.Cmp(ed1.Value) != 0 {
		t.Errorf("Expected decryption share %+v; got %+v", ed1, d1)
	}

	d3, err := Dec(pub, k3, ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}
	if d3.ID != ed3.ID || d3.Value.Cmp(ed3.Value) != 0 {
		t.Errorf("Expected decryption share %+v; got %+v", ed3, d3)
	}

	d4, err := Dec(pub, k4, ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}
	if d4.ID != ed4.ID || d4.Value.Cmp(ed4.Value) != 0 {
		t.Errorf("Expected decryption share %+v; got %+v", ed4, d4)
	}
}

func TestRecover(t *testing.T) {
	// 'Hello world', padded to 64 bytes
	msg := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	pub := PublicKey{
		SchnorrGroup: SchnorrGroup{
			P: big.NewInt(23),
			Q: big.NewInt(11),
			G: big.NewInt(4),
		},
		Y: big.NewInt(16), // x = 2
	}

	// // Three keyshares out of a 3-out-of-5 secret share of x
	// keyShares := []PrivateKeyShare{
	// 	PrivateKeyShare(secretshare.Share{ID: 1, Value: 4}}),
	// 	PrivateKeyShare(secretshare.Share{ID: 3, Value: 14}}),
	// 	PrivateKeyShare(secretshare.Share{ID: 4, Value: 22}}),
	// }

	// Ciphertext encoding of message above
	ctxt := Ciphertext{
		R: big.NewInt(3), // r = 4
		C: []byte{0xBA, 0x1E, 0x37, 0x94, 0xBC, 0x7E, 0xD5, 0xD4, 0xC9, 0x0, 0x6B, 0x9F, 0xEF, 0x89, 0xD8, 0x83, 0x41, 0x5B, 0x5A, 0xDB, 0xD6, 0xA8, 0x40, 0x30, 0xCB, 0x1F, 0x35, 0xE6, 0xA6, 0xC0, 0x26, 0xE6, 0x5C, 0x60, 0xFB, 0x99, 0xF5, 0x62, 0xF7, 0xEB, 0x9F, 0x77, 0xF3, 0xDE, 0xC5, 0x0, 0x14, 0x73, 0x44, 0x1D, 0x2C, 0x55, 0x86, 0xB5, 0x4D, 0x9B, 0x99, 0x9C, 0xF4, 0xBD, 0x79, 0xE, 0x4C, 0x56},
	}

	// 3-out-of-5 decryption shares of ciphertext above
	decryptionShares := []DecryptionShare{
		DecryptionShare(secretshare.Share{ID: 1, Value: big.NewInt(4)}),
		DecryptionShare(secretshare.Share{ID: 3, Value: big.NewInt(4)}),
		DecryptionShare(secretshare.Share{ID: 4, Value: big.NewInt(9)}),
	}

	recovered, err := Recover(pub, decryptionShares, ctxt)
	if err != nil {
		t.Fatalf("Recover returned error: %v", err)
	}

	if !bytes.Equal(recovered, msg) {
		t.Errorf("Recovered message did not match actual message; got %x; expected %x", recovered, msg)
	}

}

// This tests the whole thing end-to-end, with real-world keys.
// Hopefully catching any issues which might be the result of the
// handcrafted values above.
func TestIntegration(t *testing.T) {
	// 'Hello world', padded to 64 bytes
	msg := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	pub, _, privShares, err := KeyGen(1024, 256, 4, 6)
	if err != nil {
		t.Fatalf("KeyGen returned error: %v", err)
	}

	ctxt, err := Enc(pub, msg)
	if err != nil {
		t.Fatalf("Enc returned error: %v", err)
	}

	decShare1, err := Dec(pub, privShares[0], ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}

	decShare3, err := Dec(pub, privShares[2], ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}

	decShare4, err := Dec(pub, privShares[3], ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}

	decShare5, err := Dec(pub, privShares[4], ctxt)
	if err != nil {
		t.Fatalf("Dec returned error: %v", err)
	}

	decShares := []DecryptionShare{
		decShare1,
		decShare3,
		decShare4,
		decShare5,
	}

	recov, err := Recover(pub, decShares, ctxt)
	if err != nil {
		t.Fatalf("Recover returned error: %v", err)
	}
	if !bytes.Equal(msg, recov) {
		t.Errorf("Expected recovered message %x; got %x", msg, recov)
	}
}
