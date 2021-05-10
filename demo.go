package main

import (
	"bytes"
	"fmt"
	"github.com/lavode/distributed-elgamal/elgamal"
)

func main() {
	t := 2
	n := 5
	pBits := 1024
	qBits := 128

	// Zero-padded 'Hello world'
	msg := make([]byte, 64)
	copy(msg, []byte("Hello world"))

	fmt.Printf("Message = 0x%x\n", msg)

	fmt.Println("\n---------------\n")

	pub, privShares, err := KeyGen(pBits, qBits, t, n)
	if err != nil {
		fmt.Printf("Key generation failed: %v\n", err)
		return
	}
	fmt.Println("Key generation successful:")
	fmt.Printf("Public key:\n\tP = %d\n\tQ = %d\n\tg = %d\n\tY= %d\n", pub.P, pub.Q, pub.G, pub.Y)
	fmt.Println("Private key shares:")
	for _, share := range privShares {
		fmt.Printf("\t Share %d = %d\n", share.ID, share.Value)

	}

	fmt.Println("\n---------------\n")

	ctxt, err := Enc(pub, msg)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		return
	}
	fmt.Printf("Message encrypted:\n\tR = %d\n\tC = 0x%x\n", ctxt.R, ctxt.C)

	fmt.Println("\n---------------\n")

	decryptionShares := make([]elgamal.DecryptionShare, t+1)
	for i := 0; i < t+1; i++ {
		share, err := Dec(pub, privShares[i], ctxt)
		if err != nil {
			fmt.Printf("Decryption share generation failed: %v\n", err)
			return
		}

		decryptionShares[i] = share
	}
	fmt.Println("Decryption shares:")
	for _, share := range decryptionShares {
		fmt.Printf("\t Share %d = %d\n", share.ID, share.Value)
	}

	fmt.Println("\n---------------\n")

	recovered, err := Recover(pub, decryptionShares, ctxt)
	if err != nil {
		fmt.Printf("Message recovery failed: %v\n", err)
	}
	fmt.Printf("Recovered message: 0x%x\n", recovered)

	if bytes.Equal(recovered, msg) {
		fmt.Println("Recovered == Message")
	} else {
		fmt.Println("Recovered != Message")
	}
}

// KeyGen implements (t+1)-out-of-n key generation for the distributed hashed
// ElGamal cryptosystem.
func KeyGen(pBits int, qBits int, t int, n int) (elgamal.PublicKey, []elgamal.PrivateKeyShare, error) {
	pub, _, privShares, err := elgamal.KeyGen(pBits, qBits, t+1, n)
	return pub, privShares, err
}

// Enc encrypts a 64-byte message using the given public key
func Enc(pub elgamal.PublicKey, msg []byte) (elgamal.Ciphertext, error) {
	return elgamal.Enc(pub, msg)
}

// Dec generates a decryption share of the given ciphertext, based on the
// passed private key share.
func Dec(pub elgamal.PublicKey, keyShare elgamal.PrivateKeyShare, ctxt elgamal.Ciphertext) (elgamal.DecryptionShare, error) {
	return elgamal.Dec(pub, keyShare, ctxt)
}

// Recover recovers a plaintext message using t+1 independent decryption
// shares.
func Recover(pub elgamal.PublicKey, decryptionShares []elgamal.DecryptionShare, ctxt elgamal.Ciphertext) ([]byte, error) {
	return elgamal.Recover(pub, decryptionShares, ctxt)
}
