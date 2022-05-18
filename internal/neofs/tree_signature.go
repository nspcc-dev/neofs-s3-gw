/* REMOVE THIS AFTER SIGNATURE WILL BE AVAILABLE IN TREE CLIENT FROM NEOFS NODE */
package neofs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"

	"google.golang.org/protobuf/proto"
)

func (c *TreeClient) signData(buf []byte, f func(key, sign []byte)) error {
	hash := sha512.Sum512(buf)
	x, y, err := ecdsa.Sign(rand.Reader, &c.key.PrivateKey, hash[:])
	if err != nil {
		return err
	}
	sign := elliptic.Marshal(elliptic.P256(), x, y)

	f(c.key.PublicKey().Bytes(), sign)
	return nil
}

func (c *TreeClient) signRequest(requestBody proto.Message, f func(key, sign []byte)) error {
	buf, err := proto.Marshal(requestBody)
	if err != nil {
		return err
	}

	return c.signData(buf, f)
}
