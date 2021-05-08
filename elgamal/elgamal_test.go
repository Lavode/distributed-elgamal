package elgamal

import (
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

	field, err := pub.Field()
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
