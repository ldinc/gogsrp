package gogsrp

import (
	"hash"
	"math/big"
)

type Client struct {
	g          *big.Int
	N          *big.Int
	saltLength int
	saltLen    uint
	keyLen     uint
	newHash    func() hash.Hash
}

func CreateClient(g, N *big.Int, saltLength int, newHash func() hash.Hash) *Client {
	client := new(Client)
	client.g = g
	client.N = N
	client.newHash = newHash
	client.saltLength = saltLength
	client.saltLen = uint(saltLength)
	client.keyLen = 32

	return client
}

// SRP verifier creation
// x = H(salt | H(login | ":" | passw))
// verifier = g^x % N
// default rfc 5054 H = SHA1(...)
// return salt and verifier
func (client *Client) NewVerifier(login, passw []byte) ([]byte, *big.Int, error) {
	salt, err := RandomBytes(client.saltLen)
	if err != nil {
		return nil, nil, err
	}
	x := client.computeHashedSaltedId(salt, login, passw)
	verifier := new(big.Int)
	verifier = verifier.Exp(client.g, x, client.N)
	return salt, verifier, nil
}

func (client *Client) computeHashedSaltedId(salt, login, passw []byte) *big.Int {
	id := client.newHash()
	id.Write(login)
	id.Write([]byte(":"))
	id.Write(passw)
	hash := client.newHash()
	hash.Write(salt)
	hash.Write(id.Sum(nil))
	x := new(big.Int)
	x = x.SetBytes(hash.Sum(nil))
	return x
}

func (client *Client) NewPrivateKey() (*big.Int, error) {
	rand, err := RandomBytes(client.keyLen)
	if err != nil {
		return nil, err
	}
	sk := new(big.Int)
	sk = sk.SetBytes(rand)
	return sk, nil
}

func (client *Client) NewPublicKey(sk *big.Int) (*big.Int, error) {
	pk := new(big.Int)
	pk = pk.Exp(client.g, sk, client.N)
	return pk, nil
}

func (client *Client) GetPremasterSecret(clientPK, clientSK, serverPK *big.Int, salt, login, password []byte) *big.Int {
	u, _ := CommonHash(clientPK, serverPK, client.newHash)
	x := client.computeHashedSaltedId(salt, login, password)
	y := new(big.Int)
	y = y.Exp(client.g, x, client.N)

	khash := client.newHash()
	khash.Write(client.N.Bytes())
	khash.Write(Pad(client.g.Bytes()))
	hash := khash.Sum(nil)
	k := new(big.Int)
	k = k.SetBytes(hash)

	z := new(big.Int)
	z = z.Mul(k, y)
	b := new(big.Int)
	b = b.Sub(serverPK, z)

	y = y.Mul(u, x)
	a := new(big.Int)
	a = a.Add(clientSK, y)
	secret := new(big.Int)
	secret = secret.Exp(b, a, client.N)

	return secret
}
