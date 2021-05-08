package elgamal

import (
	"github.com/lavode/secret-sharing/gf"
	"github.com/lavode/secret-sharing/secretshare"
	"math/big"
)

// PublicKey represents a public key of the ElGamal cryptosystem.
type PublicKey struct {
	SchnorrGroup

	// Public key y = g^x mod p
	Y *big.Int
}

// Field returns the finite field over which the ElGamal cryptosystem is
// defined.
func (pk *PublicKey) Field() (gf.GF, error) {
	return gf.NewGF(pk.P)
}

// PrivateKey represents a private key of the ElGamal cryptosystem.
type PrivateKey struct {
	// Private exponent from (Z / qZ)
	X *big.Int
}

// PrivateKeyShare represents a private key share of the distributed ElGamal
// cryptosystem.
type PrivateKeyShare secretshare.Share

// KeyGen implements key generation for a distributed ElGamal cryptosystem. It
// is to be executed by a trusted dealer, who can then send out the individual
// key shares.
//
// Secret sharing is based on polynomials over a finite field.
//
// Parameters:
// - pBits: Bit length of modulus p of multiplicative group of integers modulo p
// - qBits: Bit length of prime order of subgroup G over which ElGamal operates
// - t: Number of secret shares which should be able to reconstruct private key
// - n: Number of total secret shares to generate
func KeyGen(pBits int, qBits int, t int, n int) (PublicKey, PrivateKey, []PrivateKeyShare, error) {
	var pub PublicKey
	var priv PrivateKey
	shares := make([]PrivateKeyShare, n)

	schnorr, err := GenerateSchnorrGroup(pBits, qBits)
	if err != nil {
		return pub, priv, shares, err
	}

	pub.P = schnorr.P
	pub.Q = schnorr.Q
	pub.G = schnorr.G

	// The private key x is an element of (Z/qZ), such that then g^x is an
	// element of the subgroup G.
	zq, err := gf.NewGF(pub.Q)
	if err != nil {
		return pub, priv, shares, err
	}
	x, err := zq.Rand()
	if err != nil {
		return pub, priv, shares, err
	}
	priv.X = x

	// Public key is g^x mod p
	zp, err := pub.Field()
	if err != nil {
		return pub, priv, shares, err
	}
	pub.Y = zp.Exp(pub.G, x)

	tnShares, _, err := secretshare.TOutOfN(priv.X, t, n, zp)
	if err != nil {
		return pub, priv, shares, err
	}
	for i, share := range tnShares {
		shares[i] = PrivateKeyShare(share)
	}

	return pub, priv, shares, nil
}

func Enc(pk PublicKey, message []byte) *big.Int {
	var ciphertext = &big.Int{}

	return ciphertext
}

func Dec(pk PublicKey, sk PrivateKeyShare, ciphertext *big.Int) *big.Int {
	var decryptionShare = &big.Int{}

	return decryptionShare
}

func Recover(pk PublicKey, decryptionShares []*big.Int, ciphertext *big.Int) *big.Int {
	var msg = &big.Int{}

	return msg
}
