package key

import (
	"context"
	"fmt"
	aw "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"log/slog"
)

type (
	// Getter interface allows us to define the behaviour of our key manager. This
	// behaviour is then implemented by the AwsGetter struct. The GetPublicKey method
	// takes a GetRequest struct pointer as an argument and returns a byte slice containing
	// the public key or an error.
	Getter interface {
		GetPublicKey() ([]byte, error)
	}

	// Client interface defines an abstraction/wrapper around kms.Client. This is
	// useful so that our key.AWSManager can depend on an abstraction such that the
	// behaviour can be easily stubbed out for testing.
	Client interface {
		GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (
			*kms.GetPublicKeyOutput, error)
	}

	// AwsGetter struct is an implementation of the Getter interface. It contains the
	// Client wrapper for testing purposes. It's constructor will set the implementation
	// of the wrapper to the real kms.Client from the AWS SDK, it wil also set the keyID
	// field to the KMS_KEY_ID environment variable.
	AwsGetter struct {
		Client Client
		KeyID  string
	}
)

func NewClient() (*kms.Client, error) {
	conf, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to load SDK config: %v", err))
		return nil, err
	}

	return kms.NewFromConfig(conf), nil
}

func (get *AwsGetter) GetPublicKey() ([]byte, error) {
	result, err := get.Client.GetPublicKey(context.TODO(), &kms.GetPublicKeyInput{
		KeyId: aw.String(get.KeyID)})
	if err != nil {
		return nil, fmt.Errorf("unable to get public key from KMS: %w", err)
	}

	return result.PublicKey, nil
}
