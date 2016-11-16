package test

import (
	"crypto/sha1"
	"fmt"
	"github.com/ldinc/gogsrp"
	"math/big"
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

// x = SHA1(s | SHA1(I | ":" | P))
func ExampleComputeIdHash() {
	x := computeHashedSaltedId(salt, []byte(loginString), []byte(passwString))
	fmt.Printf("x = %X\n", x.Bytes())
	// Output: x = 94B7555AABE9127CC58CCF4993DB6CF84D16C124
}

// v = g^x % N
func ExampleComputeVerifier() {
	x, _ := new(big.Int).SetString("94B7555AABE9127CC58CCF4993DB6CF84D16C124", 16)
	g, _ := new(big.Int).SetString(gString1024, 16)
	N, _ := new(big.Int).SetString(NString1024, 16)
	v := new(big.Int).Exp(g, x, N)
	fmt.Printf("v = %X\n", v.Bytes())
	// Output: v = 7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB
}

// B = k*v + g^b % N
func ExampleComputeServerPublicKey() {
	N, _ := new(big.Int).SetString(NString1024, 16)
	g, _ := new(big.Int).SetString(gString1024, 16)
	x, _ := new(big.Int).SetString("94B7555AABE9127CC58CCF4993DB6CF84D16C124", 16)
	v := new(big.Int).Exp(g, x, N)
	//k, _ := new(big.Int).SetString("7556AA045AEF2CDD07ABAF0F665C3E818913186F", 16)
	server := gogsrp.CreateServer(g, N, 32, sha1.New)
	b, _ := new(big.Int).SetString(bString, 16)
	B, _ := server.NewPublicKey(b, v)
	//y := new(big.Int)
	//y = y.Exp(g, b, N)
	//xx := new(big.Int).Mul(k, v)
	//pk := new(big.Int)
	//pk = pk.Add(xx, y)
	/*B = pk.Rem(pk, N)*/
	fmt.Printf("B = %X\n", B.Bytes())
	// Output: B = BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58
}

func computeHashedSaltedId(salt, login, passw []byte) *big.Int {
	id := sha1.New()
	id.Write(login)
	id.Write([]byte(":"))
	id.Write(passw)
	hash := sha1.New()
	hash.Write(salt)
	hash.Write(id.Sum(nil))
	x := new(big.Int)
	x = x.SetBytes(hash.Sum(nil))
	return x
}
