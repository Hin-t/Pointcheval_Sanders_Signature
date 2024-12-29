package Models

import (
	"crypto/sha256"
	"github.com/cloudflare/bn256"
	"math/big"
)

type Verifier struct {
	PrivateKey *big.Int
	PublicKey  *bn256.G2
}

// Verify 验证者进行签名验证
func (v *Verifier) Verify(pp PublicParams, sig *Signature, pubKey_KGC, Y1, Y2 *bn256.G2, FID []byte) bool {
	sigma1 := sig.sigma1
	sigma2 := sig.sigma2
	fidHashBytes := sha256.Sum256(FID)
	fidHashBigInt := big.NewInt(0).SetBytes(fidHashBytes[:])

	median1 := new(bn256.G2).ScalarMult(pubKey_KGC, fidHashBigInt)
	median2 := new(bn256.G2).ScalarMult(Y1, sig.msg[0])
	median3 := new(bn256.G2).Add(median1, median2)

	pair1 := bn256.Pair(sigma1, median3)

	median4 := new(bn256.G1).ScalarMult(sigma1, v.PrivateKey)

	pair2 := bn256.Pair(median4, Y2)

	pair3 := bn256.Pair(sigma2, pp.BaseG2)

	return new(bn256.GT).Add(pair1, pair2).String() == pair3.String()
}

// AggSignature 验证者进行聚合签名
func (v *Verifier) AggSignature(sig []*Signature) *Signature {
	aggSig := &Signature{}
	for _, i := range sig {
		aggSig.msg = append(aggSig.msg, i.msg[0])
	}
	aggSig.sigma1 = sig[0].sigma1
	sigma2 := sig[0].sigma2
	for i := 1; i < len(sig); i++ {
		sigma2 = new(bn256.G1).Add(sigma2, sig[i].sigma2)
	}
	aggSig.sigma2 = sigma2
	return aggSig
}

// AggVerify 聚合验证
func (v *Verifier) AggVerify(pp PublicParams, AggSig *Signature, FIDs [][]byte, pubKey_KGC *bn256.G2, Y1s, Y2s []*bn256.G2) bool {
	sigma1 := AggSig.sigma1
	sigma2 := AggSig.sigma2
	msg := AggSig.msg
	fidHashByte := sha256.Sum256(FIDs[0])
	fidHashBigInt := big.NewInt(0).SetBytes(fidHashByte[:])
	median1 := new(bn256.G2).ScalarMult(pubKey_KGC, fidHashBigInt)
	median2 := median1

	median3 := new(bn256.G2).ScalarMult(Y1s[0], msg[0])
	median4 := median3

	median5 := Y2s[0]

	for i := 1; i < len(FIDs); i++ {
		fidHashByte = sha256.Sum256(FIDs[i])
		fidHashBigInt = big.NewInt(0).SetBytes(fidHashByte[:])
		median1 = new(bn256.G2).ScalarMult(pubKey_KGC, fidHashBigInt)
		median2 = new(bn256.G2).Add(median1, median2)

		median3 = new(bn256.G2).ScalarMult(Y1s[i], msg[i])
		median4 = new(bn256.G2).Add(median4, median3)

		median5 = new(bn256.G2).Add(median5, Y2s[i])
	}

	median6 := new(bn256.G2).Add(median2, median4)
	median7 := new(bn256.G1).ScalarMult(sigma1, v.PrivateKey)

	pair1 := bn256.Pair(sigma1, median6)
	pair2 := bn256.Pair(median7, median5)
	pair3 := bn256.Pair(sigma2, pp.BaseG2)

	return new(bn256.GT).Add(pair1, pair2).String() == pair3.String()
}
