package Models

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

type Device struct {
	PartialKey *bn256.G2
	PrivateKey [2]*big.Int
}
