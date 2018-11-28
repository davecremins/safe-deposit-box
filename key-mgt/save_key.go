package keymgt

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
)

type keyEncoding struct {
	block   *pem.Block
	keyType string
}

// TODO: File creation should not be part of this package
// 	 We should write to an io.Writer and rename to encodePemBlockToOutput
func CreateFile(key interface{}) string {
	keyEncodingData, err := pemBlockForKey(key)
	if err != nil {
		panic(err)
	}

	fileName := createFileName(keyEncodingData)
	keyOut, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer keyOut.Close()
	fmt.Println("Key file created", fileName)
	pem.Encode(keyOut, keyEncodingData.block)
	return fileName
}

func pemBlockForKey(key interface{}) (*keyEncoding, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		pubkey_bytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			panic(err)
		}
		return &keyEncoding{
			&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubkey_bytes},
			"_public",
		}, nil
	case *rsa.PrivateKey:
		return &keyEncoding{
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)},
			"_private",
		}, nil
	default:
		return nil, fmt.Errorf("Unsupported key type %s", reflect.TypeOf(k).String())
	}
}

func createFileName(keyEncodingData *keyEncoding) string {
	var fileName bytes.Buffer
	fileName.WriteString("rsa")
	fileName.WriteString(keyEncodingData.keyType)
	fileName.WriteString(".pem")
	return fileName.String()
}
