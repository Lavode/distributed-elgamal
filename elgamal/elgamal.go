package elgamal

import (
	"crypto/sha512"
	"fmt"
	"github.com/lavode/secret-sharing/gf"
	"github.com/lavode/secret-sharing/secretshare"
	"math/big"
)

// SHA512
const hashByteSize int = 64

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

type DecryptionShare secretshare.Share

type Ciphertext struct {
	R *big.Int
	C []byte
}

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

	// (Z/qZ) is used for:
	// - Generation of private key x, such that `g^x` is an element of G
	// - Secret sharing using polynomials over (Z/qZ)
	zq, err := gf.NewGF(pub.Q)
	if err != nil {
		return pub, priv, shares, err
	}

	// (Z/pZ) is used for all operations *within* G, as it's a subgroup of
	// (Z/pZ)
	zp, err := pub.Field()
	if err != nil {
		return pub, priv, shares, err
	}

	x, err := zq.Rand()
	if err != nil {
		return pub, priv, shares, err
	}
	priv.X = x

	pub.Y = zp.Exp(pub.G, x)

	tnShares, _, err := secretshare.TOutOfN(priv.X, t, n, zq)
	if err != nil {
		return pub, priv, shares, err
	}
	for i, share := range tnShares {
		shares[i] = PrivateKeyShare(share)
	}

	return pub, priv, shares, nil
}

func Enc(pub PublicKey, message []byte) (Ciphertext, error) {
	var ctxt Ciphertext
	// Using SHA512
	ctxt.C = make([]byte, hashByteSize)

	if len(message) > hashByteSize {
		return ctxt, fmt.Errorf("Message must be at most %d bytes; got %d", hashByteSize, len(message))
	}

	// This will implicitly pad with zero-bytes, if the input message is <hashByteSize byte
	msg := make([]byte, hashByteSize)
	copy(msg, message)

	zq, err := gf.NewGF(pub.Q)
	if err != nil {
		return ctxt, err
	}
	zp, err := pub.Field()
	if err != nil {
		return ctxt, err
	}

	r, err := zq.Rand()
	if err != nil {
		return ctxt, err
	}
	ctxt.R = zp.Exp(pub.G, r) // g^r = R

	yr := zp.Exp(pub.Y, r) // y^r

	key := sha512.Sum512(yr.Bytes())

	for i, keyByte := range key {
		ctxt.C[i] = msg[i] ^ keyByte
	}

	return ctxt, nil
}

func Dec(pub PublicKey, keyShare PrivateKeyShare, ctxt Ciphertext) (DecryptionShare, error) {
	decryptionShare := DecryptionShare(
		secretshare.Share{
			ID: keyShare.ID,
		},
	)

	zp, err := pub.Field()
	if err != nil {
		return decryptionShare, err
	}

	// Secret sharing happens over (Z/pZ)
	decryptionShare.Value = zp.Exp(ctxt.R, keyShare.Value) // R^{x_i} mod p

	return decryptionShare, nil
}

func Recover(pub PublicKey, decryptionShares []DecryptionShare, ctxt Ciphertext) ([]byte, error) {
	msg := make([]byte, hashByteSize)

	xs := make([]*big.Int, len(decryptionShares))
	for i, share := range decryptionShares {
		xs[i] = big.NewInt(int64(share.ID))
	}

	zp, err := pub.Field()
	if err != nil {
		return msg, err
	}

	// Mind that secret sharing happens over (Z/qZ)
	zq, err := gf.NewGF(pub.Q)
	if err != nil {
		return msg, err
	}

	// Starting with 1, as identity of multiplication
	z := big.NewInt(1)

	for i, share := range decryptionShares {
		// Polynomial's coefficients (and such also lagrange
		// coefficients) are over (Z/qZ)
		bp := gf.BasePolynomial(i, xs, zq)
		// But the value we reconstruct is in G, so we operate over (Z/pZ)
		factor := zp.Exp(share.Value, bp)
		z = zp.Mul(z, factor)
	}

	key := sha512.Sum512(z.Bytes())

	for i, keyByte := range key {
		msg[i] = ctxt.C[i] ^ keyByte
	}

	return msg, nil
}
