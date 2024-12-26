package Models

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

type Key struct {
	PrivateKey *big.Int
	PublicKey  *bn256.G2
}
