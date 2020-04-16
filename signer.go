package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha256"
	"fmt"
	"math/big"
)

var opts = &rsa.PSSOptions{
	SaltLength: rsa.PSSSaltLengthAuto,
	Hash:       crypto.SHA256,
}

func Sign(rawTransaction []byte, n string, d string, dp string, dq string) ([]byte, error) {
	fmt.Println("n =", n)
	fmt.Println("d =", d)
	fmt.Println("dp =", dp)
	fmt.Println("dq =", dq)
	var ok bool
	keyN := new(big.Int)
	keyN, ok = keyN.SetString(n, 10)
	if !ok {
		fmt.Println("SetString: error")
		return nil, nil
	}
	fmt.Println(keyN)

	keyD := new(big.Int)
	keyD, ok = keyD.SetString(d, 10)
	if !ok {
		fmt.Println("SetString: error")
		return nil, nil
	}
	fmt.Println(keyD)

	keyDp := new(big.Int)
	keyDp, ok = keyDp.SetString(dp, 10)
	if !ok {
		fmt.Println("SetString: error")
		return nil, nil
	}
	fmt.Println(keyDp)

	keyDq := new(big.Int)
	keyDq, ok = keyDq.SetString(dq, 10)
	if !ok {
		fmt.Println("SetString: error")
		return nil, nil
	}
	fmt.Println(keyDq)
	pubKey := &rsa.PublicKey{N: keyN, E: 65537}

	primes := make([]*big.Int, 2)
	primes[0] = keyDp
	primes[1] = keyDq
	priv := &rsa.PrivateKey{D: keyD, PublicKey: *pubKey, Primes: primes}

	rng := rand.Reader
	hashed := sha256.Sum256(rawTransaction)
	sig, err := rsa.SignPSS(rng, priv, crypto.SHA256, hashed[:], opts)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
