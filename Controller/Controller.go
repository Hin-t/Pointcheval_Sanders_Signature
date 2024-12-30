package Controller

import (
	"AggregateSignature/Models"
	"math/big"
)

const Secret = 1024

var (
	pp  = Models.NewPublicParams()
	kgc = &Models.KGC{
		Key: pp.GenerateKeyPair1(),
	}
	device = &Models.Device{}
)

// AssemblyKey 组装密钥
func AssemblyKey(FID []byte) {
	device.PartialKey = kgc.PartialKey(pp, FID)
	device.GenerateDeviceKeyPair(pp)

	device.PrivateKey.PartialKey = device.PartialKey
	device.PrivateKey.PriKey1 = device.Keys[0].PrivateKey
	device.PrivateKey.PriKey2 = device.Keys[1].PrivateKey

	device.PublicKey.FID = FID
	device.PublicKey.PubKey1 = device.Keys[0].PublicKey
	device.PublicKey.PubKey2 = device.Keys[1].PublicKey
	device.Secret = big.NewInt(Secret)
}
