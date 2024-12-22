package Signature

import (
	"crypto/rand"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

type PublicParams struct {
	BaseG1 *bn256.G1
	BaseG2 *bn256.G2
	BaseGT *bn256.GT
	Order  *big.Int
}
type PrivateKey struct {
	PrivateKey []*big.Int
	PublicKey  []*bn256.G2
}

type Pointcheval_Sanders_Signature struct {
	PublicParams *PublicParams
	PriKey       *PrivateKey
	Message      []*big.Int
	Signature    []*bn256.G1
	Count        int
}

// 初始化公共参数
func NewPublicParams() *PublicParams {
	return &PublicParams{
		Order:  bn256.Order,
		BaseG1: new(bn256.G1).ScalarBaseMult(big.NewInt(1)), // G1 的基点
		BaseG2: new(bn256.G2).ScalarBaseMult(big.NewInt(1)), // G2 的基点
		BaseGT: new(bn256.GT).ScalarBaseMult(big.NewInt(1)), // G2 的基点
	}
}

// GenerateKeyPair GenerateKeyPair生成密钥对
func (pp *PublicParams) GenerateKeyPair() (*big.Int, *bn256.G2) {
	privateKey, _ := rand.Int(rand.Reader, pp.Order) // 生成随机私钥
	publicKey := pp.BaseG2.ScalarBaseMult(privateKey)
	return privateKey, publicKey
}

// 验证公私钥
func (ps *Pointcheval_Sanders_Signature) VerifyKey() bool {
	var b bool = true
	for i := 0; i < ps.Count; i++ {
		b = b && (ps.PriKey.PublicKey[i] == ps.PublicParams.BaseG2.ScalarBaseMult(ps.PriKey.PrivateKey[i]))
	}
	return b
}

// Setup 初始化公共参数
func (ps *Pointcheval_Sanders_Signature) Setup() {
	// 初始化公共参数
	ps.PublicParams = NewPublicParams()
	// 初始化公私钥
	for i := 0; i < ps.Count; i++ {
		ps.PriKey.PrivateKey[i], ps.PriKey.PublicKey[i] = ps.PublicParams.GenerateKeyPair()
	}
}

func (ps *Pointcheval_Sanders_Signature) Sign() (sigma1, sigma2 *bn256.G1) {
	h := new(bn256.G1).ScalarMult(ps.PublicParams.BaseG1, big.NewInt(1))
	sigma1 = h
	pow := ps.PriKey.PrivateKey[0]
	for i := 1; i < ps.Count; i++ {
		pow.Add(pow, new(big.Int).Mul(ps.Message[i], ps.PriKey.PrivateKey[i]))
	}
	sigma2 = new(bn256.G1).ScalarMult(sigma1, pow)
	ps.Signature = []*bn256.G1{sigma1, sigma2}
	return sigma1, sigma2
}

func (ps *Pointcheval_Sanders_Signature) Verify() bool {
	sigma1 := ps.Signature[0]
	sigma2 := ps.Signature[1]

	prod := ps.PriKey.PublicKey[0]

	for i := 1; i < ps.Count; i++ {
		prod.Add(prod, new(bn256.G2).ScalarMult(ps.PriKey.PublicKey[i], ps.Message[i]))
	}

	pair1 := bn256.Pair(sigma1, prod)
	pair2 := bn256.Pair(sigma2, ps.PublicParams.BaseG2)
	fmt.Printf("pair1 : %v , \n pair2 : %v\n", pair1, pair2)
	return pair1 == pair2

}

func AggrSign() {

}

func AggrVerify() {}
