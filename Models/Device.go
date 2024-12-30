package Models

import (
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

type Device struct {
	PartialKey *bn256.G1
	Keys       [2]*Key1
	PrivateKey struct {
		PartialKey *bn256.G1
		PriKey1    *big.Int
		PriKey2    *big.Int
	}
	PublicKey struct {
		FID     []byte
		PubKey1 *bn256.G2
		PubKey2 *bn256.G2
	}
	Secret *big.Int
}

// GenerateDeviceKeyPair 生成密钥对
func (d *Device) GenerateDeviceKeyPair(pp *PublicParams) {
	for i := 0; i < 2; i++ {
		d.Keys[i] = pp.GenerateKeyPair1()
	}
}

// Sign Signature
func (d *Device) Sign(pp *PublicParams, PK_v *bn256.G1, msg *big.Int) *Signature {
	signature := &Signature{}

	signature.msg = append(signature.msg, msg)
	fmt.Println("signature.msg: ", signature.msg)
	h := new(bn256.G1).ScalarMult(pp.BaseG1, d.Secret)
	signature.sigma1 = h
	fmt.Println("signature.sigma1: ", signature.sigma1)
	median1 := new(bn256.G1).ScalarMult(d.PartialKey, d.Secret)
	median2 := new(bn256.G1).ScalarMult(h, new(big.Int).Mul(d.Keys[0].PrivateKey, msg))
	median3 := new(bn256.G1).Add(median1, median2)
	median4 := new(bn256.G1).ScalarMult(PK_v, d.Keys[1].PrivateKey)
	median5 := new(bn256.G1).Add(median3, median4)

	signature.sigma2 = median5
	fmt.Println("signature.sigma2: ", signature.sigma2)
	fmt.Println("signature: ", signature)
	return signature
}
