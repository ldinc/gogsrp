package gogsrp

import (
	"fmt"
	"hash"
	"math/big"
)

type Client struct {
	g          *big.Int
	N          *big.Int
	saltLength int
	newHash    func() hash.Hash
}

func CreateClient(g, N *big.Int, saltLength int, newHash func() hash.Hash) *Client {
	client := new(Client)
	client.g = g
	client.N = N
	client.newHash = newHash
	client.saltLength = saltLength

	return client
}

func (client *Client) GetRegisterData(login, passw []byte) ([]byte, []byte, *big.Int, error) {
	salt, verifier, err := client.CreateVerifier(login, passw)
	return login, salt, verifier, err
}

// SRP verifier creation
// x = H(salt | H(login | ":" | passw))
// verifier = g^x % N
// default rfc 5054 H = SHA1(...)
// return salt and verifier
func (client *Client) CreateVerifier(login, passw []byte) ([]byte, *big.Int, error) {
	id := client.newHash()
	id.Write(login)
	id.Write([]byte(":"))
	id.Write(passw)
	hashedId := id.Sum(nil)
	fmt.Printf("hashed id = %x\n", hashedId)
	fmt.Printf("hashed id as string = [%s]\n", string(hashedId))
	salt, err := ReadRand(client.saltLength)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("salt = %x\n", salt)
	fmt.Printf("salt str = [%s]\n", string(salt))
	hash := client.newHash()
	hash.Write(salt)
	hash.Write(hashedId)
	hashedSaltedId := hash.Sum(nil)
	fmt.Printf("H(salt | H(login | \":\" | passw)) = %x\n", hashedSaltedId)
	x := big.NewInt(0).SetBytes(hashedSaltedId)
	verifier := new(big.Int)
	verifier = verifier.Exp(client.g, x, client.N)
	fmt.Println("g^x % N = ", verifier)
	return salt, verifier, nil
}

// The premaster secret is calculated by client.
// N, g, salt, serverPublic (B) gains from server
//
func (client *Client) CreatePremasterSecret(login, passw []byte, serverPK *big.Int, salt []byte) {
	clientSK := big.NewInt(1111)
	clientPK := new(big.Int)
	clientPK = clientPK.Exp(client.g, clientSK, client.N)
	fmt.Println("client public key = ", clientPK)
	// test code above...
	hash := client.newHash()
	hash.Write(clientPK.Bytes())
	hash.Write(serverPK.Bytes())
	u := new(big.Int)
	u.SetBytes(hash.Sum(nil))
	hash = client.newHash()
	hash.Write(client.N.Bytes())
	hash.Write(client.g.Bytes())
	k := new(big.Int)
	k.SetBytes(hash.Sum(nil))
	hash = client.newHash()
	hash.Write(login)
	hash.Write([]byte(":"))
	hash.Write(passw)
	id := hash.Sum(nil)
	hash = client.newHash()
	hash.Write(salt)
	hash.Write(id)
	hashedSaltedId := hash.Sum(nil)
	x := new(big.Int)
	x.SetBytes(hashedSaltedId)
	fmt.Println("test x = ", x)
	z := new(big.Int)
	z = z.Exp(client.g, x, client.N)
	t := new(big.Int)
	t = t.Mul(k, z)
	z = z.Sub(serverPK, t)
	t = t.Mul(u, x)
	y := new(big.Int)
	y = y.Add(clientSK, t)
	t = t.Mod(y, client.N)
	premasterSecret := new(big.Int)
	premasterSecret = premasterSecret.Exp(z, t, client.N)
	fmt.Println("client premaster secret = ", premasterSecret)

}

func (client *Client) Info() string {
	res := fmt.Sprintf("g:%s\nn:%s\n", client.g, client.N)
	return res
}
