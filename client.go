package gogrsp

import (
	"fmt"
	"math/big"
)

type Client struct {
	g *big.Int
	N *big.Int
}

func CreateClient(g, N *big.Int) *Client {
	client := new(Client)
	client.g = g
	client.N = N

	return client
}

func (client *Client) Info() string {
	res := fmt.Sprintf("g:%s\nn:%s\n", client.g, client.N)
	return res
}
