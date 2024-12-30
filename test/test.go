package main

import (
	"AggregateSignature/Models"
	"bytes"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
	"time"
)

const MessageNum = 4

const Secret = 1024

var (
	pp  = Models.NewPublicParams()
	kgc = &Models.KGC{
		Key: pp.GenerateKeyPair1(),
	}
	device1 = &Models.Device{}
	device2 = &Models.Device{}
	device3 = &Models.Device{}

	verifier = &Models.Verifier{
		Key: pp.GenerateKeyPair2(),
	}
)

// AssemblyKey 组装密钥
func AssemblyKey(device *Models.Device, FID []byte) {
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

func ASTest() {
	AssemblyKey(device1, []byte("name1"))
	AssemblyKey(device2, []byte("name2"))
	AssemblyKey(device3, []byte("name3"))
	//fmt.Println(kgc)
	//fmt.Println(pp)
	//fmt.Println(device)
	//fmt.Println(verifier)
	start := time.Now() // 记录开始时间
	sig1 := device1.Sign(pp, verifier.Key.PublicKey, big.NewInt(102))
	elapsed := time.Since(start) // 计算耗时
	fmt.Println("sig1:", sig1)
	fmt.Printf("Function Sign execution took %s\n", elapsed)

	start = time.Now() // 记录开始时间
	b := verifier.Verify(pp, sig1, kgc.Key.PublicKey, device1)
	elapsed = time.Since(start) // 计算耗时
	fmt.Printf("Function Verify execution took %s\n", elapsed)
	fmt.Println("b:", b)

	start = time.Now() // 记录开始时间
	sig2 := device2.Sign(pp, verifier.Key.PublicKey, big.NewInt(102))
	elapsed = time.Since(start) // 计算耗时
	fmt.Println("sig2:", sig2)
	fmt.Printf("Function Sign execution took %s\n", elapsed)

	start = time.Now() // 记录开始时间
	b = verifier.Verify(pp, sig2, kgc.Key.PublicKey, device2)
	elapsed = time.Since(start) // 计算耗时
	fmt.Printf("Function Verify execution took %s\n", elapsed)
	fmt.Println("b:", b)

	start = time.Now() // 记录开始时间
	sig3 := device3.Sign(pp, verifier.Key.PublicKey, big.NewInt(106))
	elapsed = time.Since(start) // 计算耗时
	fmt.Println("sig3:", sig2)
	fmt.Printf("Function Sign execution took %s\n", elapsed)

	start = time.Now() // 记录开始时间
	b = verifier.Verify(pp, sig3, kgc.Key.PublicKey, device3)
	elapsed = time.Since(start) // 计算耗时
	fmt.Printf("Function Verify execution took %s\n", elapsed)
	fmt.Println("b:", b)

	start = time.Now() // 记录开始时间
	aggSig := verifier.AggSignature([]*Models.Signature{sig1, sig2, sig3})
	fmt.Printf("Function AggSignature execution took %s\n", elapsed)

	devices := []*Models.Device{device1, device2, device3}

	start = time.Now() // 记录开始时间
	b = verifier.AggVerify(pp, aggSig, devices, kgc.Key.PublicKey)
	fmt.Printf("Function AggVerify execution took %s\n", elapsed)
	fmt.Println("AggVerify b:", b)
}

func main() {
	ASTest()
	//GTTest()
}

// 配对测试
func PairTest() {
	baseG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	baseG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	//baseGT := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	// 私钥
	x := big.NewInt(100)
	fmt.Println("privateKey:", x)
	// 公钥
	X := new(bn256.G2).ScalarMult(baseG2, x)
	fmt.Println("publicKey:", X)
	message := big.NewInt(20)
	fmt.Println("message:", message)

	signature := new(bn256.G1).ScalarMult(baseG1, new(big.Int).Mul(message, x))
	fmt.Println("signature:", signature)

	pair1 := bn256.Pair(baseG1, new(bn256.G2).ScalarMult(baseG2, message))
	fmt.Println("pair1:", pair1)
	pair2 := bn256.Pair(signature, baseG2)
	fmt.Println("pair2:", pair2)

	fmt.Println(bytes.Equal(pair1.Marshal(), pair2.Marshal()))

}

// 配对运算
func GTTest() {
	x1 := big.NewInt(100)
	x2 := big.NewInt(150)
	x3 := new(big.Int).Add(x1, x2)

	y1 := new(bn256.G1).ScalarMult(pp.BaseG1, x1)
	y2 := new(bn256.G1).ScalarMult(pp.BaseG1, x2)
	y3 := new(bn256.G1).ScalarMult(pp.BaseG1, x3)

	pair1 := bn256.Pair(y1, pp.BaseG2)
	pair2 := bn256.Pair(y2, pp.BaseG2)
	pair3 := bn256.Pair(y3, pp.BaseG2)

	fmt.Println("pair:", pair1, pair2, pair3)

	pair4 := new(bn256.GT).Add(pair1, pair2)

	fmt.Println("pair:", pair1, pair2, pair3, pair4)

	b := bytes.Equal(pair3.Marshal(), pair4.Marshal())
	fmt.Println("b:", b)
}
