package Models

import (
	"crypto/rand"
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

// GenerateKeyPair1 生成密钥对
func (pp *PublicParams) GenerateKeyPair1() *Key1 {
	privateKey, _ := rand.Int(rand.Reader, pp.Order) // 生成随机私钥
	publicKey := new(bn256.G2).ScalarMult(pp.BaseG2, privateKey)
	return &Key1{privateKey, publicKey}
}

// GenerateKeyPair2 生成密钥对
func (pp *PublicParams) GenerateKeyPair2() *Key2 {
	privateKey, _ := rand.Int(rand.Reader, pp.Order) // 生成随机私钥
	publicKey := new(bn256.G1).ScalarMult(pp.BaseG1, privateKey)
	return &Key2{privateKey, publicKey}
}
