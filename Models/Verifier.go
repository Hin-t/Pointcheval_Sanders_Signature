package Models

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

type Verifier struct {
	Key *Key2
}

// Verify 验证者进行签名验证
func (v *Verifier) Verify(pp *PublicParams, sig *Signature, pubKey_KGC *bn256.G2, device *Device) bool {
	sigma1 := sig.sigma1
	sigma2 := sig.sigma2
	fidHashBytes := sha256.Sum256(device.PublicKey.FID)
	fidHashBigInt := big.NewInt(0).SetBytes(fidHashBytes[:])

	median1 := new(bn256.G2).ScalarMult(pubKey_KGC, fidHashBigInt)
	median2 := new(bn256.G2).ScalarMult(device.PublicKey.PubKey1, sig.msg[0])
	median3 := new(bn256.G2).Add(median1, median2)

	pair1 := bn256.Pair(sigma1, median3)

	median4 := new(bn256.G1).ScalarMult(pp.BaseG1, v.Key.PrivateKey)

	pair2 := bn256.Pair(median4, device.PublicKey.PubKey2)

	pair3 := bn256.Pair(sigma2, pp.BaseG2)

	return bytes.Equal(new(bn256.GT).Add(pair1, pair2).Marshal(), pair3.Marshal())
}

// AggSignature 验证者进行聚合签名
func (v *Verifier) AggSignature(sigs []*Signature) *Signature {
	aggSig := &Signature{}
	for _, i := range sigs {
		aggSig.msg = append(aggSig.msg, i.msg[0])
	}
	aggSig.sigma1 = sigs[0].sigma1
	fmt.Println("aggSig.sigma1", aggSig.sigma1)
	sigma2 := sigs[0].sigma2
	for i := 1; i < len(sigs); i++ {
		sigma2 = new(bn256.G1).Add(sigma2, sigs[i].sigma2)
	}
	aggSig.sigma2 = sigma2
	fmt.Println("aggSig.sigma2", aggSig.sigma2)
	return aggSig
}

// AggVerify 聚合验证
func (v *Verifier) AggVerify(pp *PublicParams, AggSig *Signature, Devices []*Device, pubKey_KGC *bn256.G2) bool {
	sigma1 := AggSig.sigma1
	sigma2 := AggSig.sigma2
	msg := AggSig.msg
	fidHashByte := sha256.Sum256(Devices[0].PublicKey.FID)
	fidHashBigInt := big.NewInt(0).SetBytes(fidHashByte[:])

	median1 := new(bn256.G2).ScalarMult(pubKey_KGC, fidHashBigInt)
	median2 := median1

	median3 := new(bn256.G2).ScalarMult(Devices[0].PublicKey.PubKey1, msg[0])
	median4 := median3

	median5 := Devices[0].PublicKey.PubKey2

	for i := 1; i < len(Devices); i++ {
		fidHashByte = sha256.Sum256(Devices[i].PublicKey.FID)
		fidHashBigInt = big.NewInt(0).SetBytes(fidHashByte[:])

		median1 = new(bn256.G2).ScalarMult(pubKey_KGC, fidHashBigInt)
		median2 = new(bn256.G2).Add(median1, median2)

		median3 = new(bn256.G2).ScalarMult(Devices[i].PublicKey.PubKey1, msg[i])
		median4 = new(bn256.G2).Add(median4, median3)

		median5 = new(bn256.G2).Add(median5, Devices[i].PublicKey.PubKey2)
	}

	median6 := new(bn256.G2).Add(median2, median4)
	median7 := new(bn256.G1).ScalarMult(pp.BaseG1, v.Key.PrivateKey)

	pair1 := bn256.Pair(sigma1, median6)
	pair2 := bn256.Pair(median7, median5)
	pair3 := bn256.Pair(sigma2, pp.BaseG2)

	return bytes.Equal(new(bn256.GT).Add(pair1, pair2).Marshal(), pair3.Marshal())

}
