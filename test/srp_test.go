package test

import (
	"crypto/sha1"
	"fmt"
	"math/big"
	//"github.com/ldinc/gogsrp"
)

func ExampleComputeVerifierParam() {
	login := []byte(loginString)
	passw := []byte(passwString)
	id := sha1.New()
	id.Write(login)
	id.Write([]byte(":"))
	id.Write(passw)
	hash := sha1.New()
	hash.Write(salt)
	hash.Write(id.Sum(nil))
	x := new(big.Int)
	x = x.SetBytes(hash.Sum(nil))

	fmt.Printf("x = %X\n", x.Bytes())
	// Output: x = 94B7555AABE9127CC58CCF4993DB6CF84D16C124
}

func Pad(buf, N []byte) []byte {
	if len(buf) > len(N) {
		return buf
	}
	b := make([]byte, len(N))
	copy(b[len(N)-len(buf):], buf)
	return b
}

func ExampleComputeVerifierMultParam() {
	N := new(big.Int)
	N, _ = N.SetString(NString1024, 16)
	g := new(big.Int)
	g, _ = g.SetString(gString1024, 16)
	padg := Pad(g.Bytes(), N.Bytes())
	khash := sha1.New()
	khash.Write(N.Bytes())
	khash.Write(padg)
	hash := khash.Sum(nil)
	k := new(big.Int)
	k = k.SetBytes(hash)

	fmt.Printf("k = %X\n", k.Bytes())
	// Output: k = 7556AA045AEF2CDD07ABAF0F665C3E818913186F
}
