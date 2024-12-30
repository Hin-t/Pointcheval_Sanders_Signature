package Models

import (
	"crypto/sha256"
	"github.com/cloudflare/bn256"
	"math/big"
)

type KGC struct {
	Key *Key1
}

// PartialKey 为设备生成部分私钥
func (kgc *KGC) PartialKey(pp *PublicParams, FID []byte) *bn256.G1 {
	fidHashBytes := sha256.Sum256(FID)
	fidHashBigInt := big.NewInt(0).SetBytes(fidHashBytes[:])

	exp := new(big.Int).Mul(kgc.Key.PrivateKey, fidHashBigInt)
	return new(bn256.G1).ScalarMult(pp.BaseG1, exp)
}
