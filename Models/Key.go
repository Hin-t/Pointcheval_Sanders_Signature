package Models

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

type Key1 struct {
	PrivateKey *big.Int
	PublicKey  *bn256.G2
}

type Key2 struct {
	PrivateKey *big.Int
	PublicKey  *bn256.G1
}
