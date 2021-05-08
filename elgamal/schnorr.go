package elgamal

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type SchnorrGroup struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

func GenerateSchnorrGroup(pBits int, qBits int) (SchnorrGroup, error) {
	var err error
	schnorr := SchnorrGroup{}

	if qBits >= pBits {
		return schnorr, fmt.Errorf("qbits must be < pbits")
	}

	// Starting with q-order subgroup
	schnorr.Q, err = rand.Prime(rand.Reader, qBits)
	if err != nil {
		return schnorr, err
	}

	// Find a prime p such that p = q*r + 1 for some integer r
	schnorr.P = big.NewInt(0)
	for !schnorr.P.ProbablyPrime(32) {
		rBits := pBits - qBits
		r, err := RandomBits(rBits)
		if err != nil {
			return schnorr, err
		}

		// At this point, r and q both are guaranteed to have their
		// highest two bits as 1. As such, the product of the two has a
		// bit length of exactly pbits. Further the product cannot be
		// the bigmost possible pBits number, so adding 1 will not
		// cause it to overflow.

		// p = r * q + 1
		schnorr.P.SetBytes(r)
		schnorr.P.Mul(schnorr.P, schnorr.Q)
		schnorr.P.Add(schnorr.P, big.NewInt(1))
	}

	// Finally find a generator by picking random values 1 < h < p such that g = h^r mod p != 1
	schnorr.G = big.NewInt(1)
	for {
		// rand.Int produces in [0, max), we want [2, p).
		var max = &big.Int{}
		max.Set(schnorr.P)
		max.Sub(max, big.NewInt(2))

		h, err := rand.Int(rand.Reader, max) // [0, p-2)
		if err != nil {
			return schnorr, err
		}
		h.Add(h, big.NewInt(2)) // [2, p)

		var exp = &big.Int{}
		exp.Sub(schnorr.P, big.NewInt(1))
		exp.Div(exp, schnorr.Q)

		schnorr.G.Exp(h, exp, schnorr.P)

		if schnorr.G.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}

	return schnorr, nil
}
