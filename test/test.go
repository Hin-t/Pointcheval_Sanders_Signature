package main

import (
	"AggregateSignature/Signature"
	"bytes"
	"fmt"
	"github.com/cloudflare/bn256"
	"math/big"
)

func main() {

	ps := &Signature.Pointcheval_Sanders_Signature{
		PublicParams: nil,
		PriKey:       &Signature.PrivateKey{PrivateKey: make([]*big.Int, 2), PublicKey: make([]*bn256.G2, 2)},
		Count:        2,
		Message:      []*big.Int{big.NewInt(0), big.NewInt(100)},
		Signature:    make([]*bn256.G1, 2),
	}

	ps.Setup()

	ps.Sign()
	fmt.Println("privateKey:", ps.PriKey.PrivateKey)
	fmt.Println("publicKey:", ps.PriKey.PublicKey)
	fmt.Println("message:", ps.Message)
	fmt.Printf("signature (%v,%v)\n", ps.Signature[0], ps.Signature[1])

	fmt.Println("verify key:", ps.VerifyKey())
	fmt.Println("baseG1:", ps.PublicParams.BaseG1)
	fmt.Println("baseG2:", ps.PublicParams.BaseG2)
	fmt.Println("baseGT:", ps.PublicParams.BaseGT)
	fmt.Printf("verify: %v\n", ps.Verify())
	fmt.Println("privateKey:", ps.PriKey.PrivateKey)
	fmt.Println("publicKey:", ps.PriKey.PublicKey)

	//NewTest()

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

func NewTest() {
	// 基础点
	baseG1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	baseG2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	// 消息和私钥
	message := big.NewInt(20)
	x := big.NewInt(100)

	// 公钥
	X := new(bn256.G2).ScalarMult(baseG2, x)

	// 签名
	messageTimesKey := new(big.Int).Mul(message, x)
	signature := new(bn256.G1).ScalarMult(baseG1, messageTimesKey)
	fmt.Println("signature:", signature)

	// 验证配对公式
	messageInG2 := new(bn256.G2).ScalarMult(X, message)
	pair1 := bn256.Pair(baseG1, messageInG2)
	pair2 := bn256.Pair(signature, baseG2)

	fmt.Println("pair1:", pair1)
	fmt.Println("pair2:", pair2)

	// 比较配对结果
	fmt.Println("String comparison:", pair1.String() == pair2.String())
	fmt.Println("Marshal comparison:", bytes.Equal(pair1.Marshal(), pair2.Marshal()))
}
