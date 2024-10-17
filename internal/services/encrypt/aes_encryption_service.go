package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type Service struct {
}

func NewAESService() ServiceInterface {
	return &Service{}
}

func (service *Service) Encrypt(plainText string, key string) (string, error) {
	// generate cipher block from key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("error generating cipher block from key: %v", err)
	}

	// make initialization vector with random bytes
	cipherBytesList := make([]byte, aes.BlockSize+len(plainText))
	initializationVector := cipherBytesList[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		return "", fmt.Errorf("error making initialization vector with random bytes: %v", err)
	}

	// create CFB encrypter with block and initialization vector, apply XOR between cipher and plain text bytes
	stream := cipher.NewCFBEncrypter(block, initializationVector)
	stream.XORKeyStream(cipherBytesList[aes.BlockSize:], []byte(plainText))

	// encode cipher text bytes to base64 string with standard encoding
	return base64.StdEncoding.EncodeToString(cipherBytesList), nil
}

func (service *Service) Decrypt(cipherText string, key string) (string, error) {
	// decode base64 string to cipher bytes with standard encoding
	cipherBytesList, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("error decoding cipher text into bytes: %v", err)
	}

	// generate cipher block from key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("error generating cipher block from key: %v", err)
	}

	// check if cipher bytes list is too short
	if len(cipherBytesList) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// separate initialization vector from cipher bytes
	initializationVector := cipherBytesList[:aes.BlockSize]
	cipherBytesList = cipherBytesList[aes.BlockSize:]

	// create CFB deceypter with block and initialization vector, apply XOR between cipher bytes and itself
	stream := cipher.NewCFBDecrypter(block, initializationVector)
	stream.XORKeyStream(cipherBytesList, cipherBytesList)

	return base64.StdEncoding.EncodeToString(cipherBytesList), nil
}
