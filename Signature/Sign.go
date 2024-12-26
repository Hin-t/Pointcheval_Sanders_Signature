package Signature

import (
	"AggregateSignature/Models"
	"bytes"
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

type Pointcheval_Sanders_Signature struct {
	PublicParams *Models.PublicParams
	PriKey       *Models.Key
	Message      []*big.Int
	Signature    []*bn256.G1
	Count        int
}

// VerifyKey 验证公私钥
func (ps *Pointcheval_Sanders_Signature) VerifyKey() bool {
	var b bool = true
	for i := 0; i < ps.Count; i++ {
		b = b && (ps.PriKey.PublicKey[i].String() == new(bn256.G2).ScalarMult(ps.PublicParams.BaseG2, ps.PriKey.PrivateKey[i]).String())
	}
	return b
}

// Setup 初始化公共参数
func (ps *Pointcheval_Sanders_Signature) Setup() {
	// 初始化公共参数
	ps.PublicParams = Models.NewPublicParams()
	// 初始化公私钥
	for i := 0; i < ps.Count; i++ {
		ps.PriKey.PrivateKey[i], ps.PriKey.PublicKey[i] = ps.PublicParams.GenerateKeyPair()
	}
}

func (ps *Pointcheval_Sanders_Signature) Sign() (sigma1, sigma2 *bn256.G1) {
	h := new(bn256.G1).ScalarMult(ps.PublicParams.BaseG1, big.NewInt(100))
	sigma1 = h
	pow := new(big.Int).Mul(ps.PriKey.PrivateKey[0], big.NewInt(1))
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
	prod := new(bn256.G2).ScalarMult(ps.PriKey.PublicKey[0], big.NewInt(1))
	for i := 1; i < ps.Count; i++ {
		prod.Add(prod, new(bn256.G2).ScalarMult(ps.PriKey.PublicKey[i], ps.Message[i]))
	}
	pair1 := bn256.Pair(sigma1, prod)
	pair2 := bn256.Pair(sigma2, ps.PublicParams.BaseG2)
	fmt.Printf("pair1 : %v , \n pair2 : %v\n", pair1, pair2)
	return bytes.Equal(pair1.Marshal(), pair2.Marshal())

}

//func AggrSign() {
//
//}
//
//func AggrVerify() {}
