package keymgt

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"
)

type pemEncoding struct {
	block   *pem.Block
	keyType string
}

// PemEncodeKeyToOutput creates a pem encoding for the provided key
// and writes the encoded block to the provided io.Writer.
//
// A PEM type convention name is returned.
func PemEncodeKeyToOutput(key interface{}, out io.Writer) string {
	encodedData, err := createPemEncodingStructureForKey(key)
	if err != nil {
		panic(err)
	}
	pem.Encode(out, encodedData.block)
	return createPemName(encodedData)
}

func createPemEncodingStructureForKey(key interface{}) (*pemEncoding, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		pubkeyBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			panic(err)
		}
		return &pemEncoding{
			&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubkeyBytes},
			"_public",
		}, nil
	case *rsa.PrivateKey:
		return &pemEncoding{
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)},
			"_private",
		}, nil
	default:
		return nil, fmt.Errorf("Unsupported key type %s", reflect.TypeOf(k).String())
	}
}

func createPemName(encodedData *pemEncoding) string {
	var name bytes.Buffer
	name.WriteString("rsa")
	name.WriteString(encodedData.keyType)
	name.WriteString(".pem")
	return name.String()
}
