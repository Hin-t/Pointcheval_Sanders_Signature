package Models

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/cloudflare/bn256"
	"math/big"
)

type KGC struct {
	Key *Key
}

// GenerateKeyPair GenerateKeyPair生成密钥对
func (pp *PublicParams) GenerateKeyPair() *Key {
	privateKey, _ := rand.Int(rand.Reader, pp.Order) // 生成随机私钥
	publicKey := new(bn256.G2).ScalarMult(pp.BaseG2, privateKey)
	return &Key{privateKey, publicKey}
}

// PartialKey 为设备生成部分私钥
func (kgc *KGC) PartialKey(pp *PublicParams, FID []byte) *bn256.G2 {
	fidHashBytes := sha256.Sum256(FID)
	fidHashBigInt := big.NewInt(0).SetBytes(fidHashBytes[:])
	exp := new(big.Int).Mul(kgc.Key.PrivateKey, fidHashBigInt)
	return new(bn256.G2).ScalarMult(pp.BaseG2, exp)
}
