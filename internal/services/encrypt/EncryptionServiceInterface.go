package encrypt

type ServiceInterface interface {
	Encrypt(plainText string, key string) (string, error)
	Decrypt(cipherText string, key string) (string, error)
}
