package Models

import (
	"crypto/rand"
	"github.com/cloudflare/bn256"
	"math/big"
)

type KGC struct {
	Key *Key
}

type PartialKey struct {
}

// GenerateKeyPair GenerateKeyPair生成密钥对
func (pp *PublicParams) GenerateKeyPair() (*big.Int, *bn256.G2) {
	privateKey, _ := rand.Int(rand.Reader, pp.Order) // 生成随机私钥
	publicKey := new(bn256.G2).ScalarMult(pp.BaseG2, privateKey)
	return privateKey, publicKey
}

// PartialKey 为设备生成部分私钥
func (kgc *KGC) PartialKey(pp PublicParams) *bn256.G2 {
	exp := new(big.Int).Mul(kgc.Key.PrivateKey, rand.Int(rand.Reader, pp.Order))
}
