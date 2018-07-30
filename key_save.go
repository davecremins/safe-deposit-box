package keyMgt

import (
	"bytes"
	"crypto/rand"
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

func CreateRSAKeys(keySize int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		panic(err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

func ConvertPublicKeyToInterface(publicKey *rsa.PublicKey) interface{} {
	var iType interface{}
	iType = publicKey
	return iType
}

func ConvertPrivateKeyToInterface(privateKey *rsa.PrivateKey) interface{} {
	var iType interface{}
	iType = privateKey
	return iType
}

//Maybe support file location
func CreateFile(key interface{}) string {
	keyEncodingData, err := pemBlockForKey(key)
	if err != nil {
		panic(err)
	}

	fileName := createFileName(keyEncodingData)
	keyOut, err := os.Create(fileName)
	if err != nil {
		fmt.Println("failed to open %s for writing:", fileName, err)
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
		return &keyEncoding{
			&pem.Block{Type: "BEGIN RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(k)},
			"_public",
		}, nil
	case *rsa.PrivateKey:
		return &keyEncoding{
			&pem.Block{Type: "BEGIN RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)},
			"_private",
		}, nil
	default:
		return nil, fmt.Errorf("Unsupported key type %s", reflect.TypeOf(k))
	}
}

func createFileName(keyEncodingData *keyEncoding) string {
	var fileName bytes.Buffer
	fileName.WriteString("rsa")
	fileName.WriteString(keyEncodingData.keyType)
	fileName.WriteString(".pem")
	return fileName.String()
}
