package gogsrp

import (
	"fmt"
	//"hash"
	"math/big"
)

type Client struct {
	g          *big.Int
	N          *big.Int
	saltLength int
	hash       RenewableHash
}

func CreateClient(g, N *big.Int, saltLength int, hash RenewableHash) *Client {
	client := new(Client)
	client.g = g
	client.N = N
	client.hash = hash
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
	id := client.hash.New()
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
	hash := client.hash.New()
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

func (client *Client) Info() string {
	res := fmt.Sprintf("g:%s\nn:%s\n", client.g, client.N)
	return res
}
