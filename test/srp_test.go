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
	fmt.Printf("B = %X\n", B.Bytes())
	// Output: B = BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58
}

// A = g^a % N
func ExampleComputeClientPublicKey() {
	N, _ := new(big.Int).SetString(NString1024, 16)
	g, _ := new(big.Int).SetString(gString1024, 16)
	client := gogsrp.CreateClient(g, N, 32, sha1.New)
	a, _ := new(big.Int).SetString(aString, 16)
	A, _ := client.NewPublicKey(a)
	fmt.Printf("A = %X\n", A.Bytes())
	// Output: A = 61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B
}

// client premaster secret = (B - (k * g^x)) ^ (a + (u * x)) % N
func ExampleComputeClientPremasterSecret() {
	B, _ := new(big.Int).SetString(BString, 16)
	g, _ := new(big.Int).SetString(gString1024, 16)
	a, _ := new(big.Int).SetString(aString, 16)
	N, _ := new(big.Int).SetString(NString1024, 16)
	A, _ := new(big.Int).SetString(AString, 16)
	client := gogsrp.CreateClient(g, N, 32, sha1.New)
	premaster := client.GetPremasterSecret(A, a, B, salt, []byte(loginString), []byte(passwString))
	fmt.Printf("secret = %X\n", premaster.Bytes())
	// Output: secret = B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A
}

// server premaster secret = (A * v^u) ^ b % N
func ExampleComputeServerPremasterSecret() {
	B, _ := new(big.Int).SetString(BString, 16)
	g, _ := new(big.Int).SetString(gString1024, 16)
	b, _ := new(big.Int).SetString(bString, 16)
	N, _ := new(big.Int).SetString(NString1024, 16)
	A, _ := new(big.Int).SetString(AString, 16)
	v, _ := new(big.Int).SetString(vString, 16)
	server := gogsrp.CreateServer(g, N, 32, sha1.New)
	premaster := server.GetPremasterSecret(A, B, b, v)
	fmt.Printf("secret = %X\n", premaster.Bytes())
	// Output: secret = B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A
}

func ExampleComputeSessionKey() {
	secret, _ := new(big.Int).SetString(sString, 16)
	key := gogsrp.SessionKey(secret, sha1.New)
	fmt.Printf("session key = %X\n", key)
	// Output: session key = 017EEFA1CEFC5C2E626E21598987F31E0F1B11BB
}

func ExampleComputeExchangeMessage() {
	sessionKey := []byte{0x01, 0x7E, 0xEF, 0xA1, 0xCE, 0xFC, 0x5C, 0x2E, 0x62, 0x6E, 0x21, 0x59, 0x89, 0x87, 0xF3, 0x1E, 0x0F, 0x1B, 0x11, 0xBB}
	B, _ := new(big.Int).SetString(BString, 16)
	g, _ := new(big.Int).SetString(gString1024, 16)
	N, _ := new(big.Int).SetString(NString1024, 16)
	A, _ := new(big.Int).SetString(AString, 16)
	msg := gogsrp.ExchangeMessage([]byte(loginString), salt, sessionKey, g, N, A, B, sha1.New)
	fmt.Printf("exchange message = %X\n", msg)
	// Output: exchange message = 3F3BC67169EA71302599CF1B0F5D408B7B65D347
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
