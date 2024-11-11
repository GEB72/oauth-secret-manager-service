package aws

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	km "github.com/aws/aws-sdk-go-v2/service/kms"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"log/slog"
)

// SecretClient interface define an abstraction/wrapper around secretsmanager.Client.
// This is useful so that our secret.AWSManager can depend on an abstraction such that the
// behaviour can be easily stubbed out for testing.
type SecretClient interface {
	GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (
		*sm.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (
		*sm.PutSecretValueOutput, error)
	CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (
		*sm.CreateSecretOutput, error)
	DescribeSecret(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (
		*sm.DescribeSecretOutput, error)
}

// KeyClient interface defines an abstraction/wrapper around kms.Client. This is
// useful so that our key.AWSManager can depend on an abstraction such that the
// behaviour can be easily stubbed out for testing.
type KeyClient interface {
	GetPublicKey(ctx context.Context, params *km.GetPublicKeyInput, optFns ...func(*km.Options)) (
		*km.GetPublicKeyOutput, error)
}

// GetConfig gets the SDK default config from the local machines environment
// variables or configuration files. If successfully found it will return the
// aws.Config struct, otherwise it will return an error.
func GetConfig() (*aws.Config, error) {
	config, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to load SDK config: %v", err))
		return nil, err
	}

	return &config, nil
}
