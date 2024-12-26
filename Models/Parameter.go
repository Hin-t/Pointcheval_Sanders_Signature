package Models

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

type PublicParams struct {
	BaseG1 *bn256.G1
	BaseG2 *bn256.G2
	BaseGT *bn256.GT
	Order  *big.Int
}

// NewPublicParams 初始化公共参数
func NewPublicParams() *PublicParams {
	return &PublicParams{
		Order:  bn256.Order,
		BaseG1: new(bn256.G1).ScalarBaseMult(big.NewInt(1)), // G1 的基点
		BaseG2: new(bn256.G2).ScalarBaseMult(big.NewInt(1)), // G2 的基点
		BaseGT: new(bn256.GT).ScalarBaseMult(big.NewInt(1)), // G2 的基点
	}
}
