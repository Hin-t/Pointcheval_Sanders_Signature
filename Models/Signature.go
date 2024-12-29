package Models

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

type Signature struct {
	msg    []*big.Int
	sigma1 *bn256.G1
	sigma2 *bn256.G1
}
