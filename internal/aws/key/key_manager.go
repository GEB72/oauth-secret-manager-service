package key

import (
	"app/internal/aws"
	"context"
	"fmt"
	aw "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"os"
)

// Manager interface allows us to define the behaviour of our key manager. This
// behaviour is then implemented by the AWSManager struct. The GetPublicKey method
// takes a GetRequest struct pointer as an argument and returns a byte slice containing
// the public key or an error.
type Manager interface {
	GetPublicKey() ([]byte, error)
}

// AWSManager struct is an implementation of the Manager interface. It contains the
// KeyClient wrapper for testing purposes. It's constructor will set the implementation
// of the wrapper to the real kms.Client from the AWS SDK, it wil also set the keyID
// field to the KMS_KEY_ID environment variable.
type AWSManager struct {
	client aws.KeyClient
	keyID  string
}

func NewKeyManager() (*AWSManager, error) {
	cfg, err := aws.GetConfig()
	if err != nil {
		return nil, err
	}

	keyID := os.Getenv("KMS_KEY_ID")
	if keyID == "" {
		return nil, fmt.Errorf("KMS_KEY_ID environment variable not set")
	}

	return &AWSManager{kms.NewFromConfig(*cfg), keyID}, nil
}

func (m *AWSManager) GetPublicKey() ([]byte, error) {
	result, err := m.client.GetPublicKey(context.TODO(), &kms.GetPublicKeyInput{
		KeyId: aw.String(m.keyID)})
	if err != nil {
		return nil, fmt.Errorf("unable to get public key from KMS: %w", err)
	}

	return result.PublicKey, nil
}
