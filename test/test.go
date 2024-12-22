package main

import (
	"AggregateSignature/Signature"
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
	//fmt.Println("baseG1:", ps.PublicParams.BaseG1)
	//fmt.Println("baseG2:", ps.PublicParams.BaseG2)
	//fmt.Println("baseGT:", ps.PublicParams.BaseGT)
	//fmt.Printf("verify: %v", ps.Verify())
}
