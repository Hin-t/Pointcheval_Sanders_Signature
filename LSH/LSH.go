package main

import (
	"fmt"
	"github.com/RyuaNerin/go-krypto/lsh512"
)

const (
	// The size of a LSH-512 checksum in bytes.
	Size = 64
	// The size of a LSH-384 checksum in bytes.
	Size384 = 48
	// The size of a LSH-512-256 checksum in bytes.
	Size256 = 32
	// The size of a LSH-512-224 checksum in bytes.
	Size224 = 28

	// The blocksize of LSH-512, LSH-384, LSH-512-256 and LSH-512-224 in bytes.
	BlockSize = 256
)

func main() {
	lsh := lsh512.New()
	res1 := lsh.Sum([]byte("111111111351111111"))
	fmt.Println(res1)
	res2 := lsh.Sum([]byte("111111131111111112"))
	fmt.Println(res2)
	for i := 0; i < 20; i++ {
		if res1[i] != res2[i] {
			fmt.Printf("not equal: %v\n", i)
		}
	}
	fmt.Println("equal")
}
