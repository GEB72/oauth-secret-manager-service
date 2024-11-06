package secret

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"log/slog"
)

// These struct types define the structure for incoming requests to the
// Manager. PutRequest is used for both Putter and Creator methods since
// we only want to create a secret after attempting to put values into
// one and realising the secret does not exist.
type (
	GetRequest struct {
		SecretID string
	}

	PutRequest struct {
		SecretID string
		Token    string
	}

	ResolveIDRequest struct {
		UserID string
	}
)

// Manager interface is a composition of four other interfaces that all specify
// a behaviour that our secret manager implementation should implement. They
// take the request struct pointers defined above as arguments.
type (
	Manager interface {
		Getter
		Putter
		Creator
		IDResolver
	}

	Getter interface {
		GetSecret(r *GetRequest) (string, error)
	}

	Putter interface {
		PutSecret(r *PutRequest) error
	}

	Creator interface {
		CreateSecret(r *PutRequest) error
	}

	IDResolver interface {
		ResolveSecretID(r *ResolveIDRequest) (string, error)
	}
)

// AWSClient interface define an abstraction/wrapper around secretsmanager.Client.
// This is useful so that our AWSManager can depend on an abstraction that can be
// easily mocked and its behaviour stubbed out for testing.
type AWSClient interface {
	GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (
		*sm.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (
		*sm.PutSecretValueOutput, error)
	CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (
		*sm.CreateSecretOutput, error)
	DescribeSecret(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (
		*sm.DescribeSecretOutput, error)
}

// AWSManager struct is an implementation of the Manager interface. It contains the
// AWSClient wrapper for testing purposes. It's constructor will set the implementation
// of the wrapper to the real secretsmanager.Client.
type AWSManager struct {
	client AWSClient
}

func NewAWSManager() (*AWSManager, error) {
	config, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to load SDK config: %v", err))
		return nil, err
	}

	return &AWSManager{sm.NewFromConfig(config)}, nil
}

func (a *AWSManager) GetSecret(r *GetRequest) (string, error) {
	result, err := a.client.GetSecretValue(context.TODO(), &sm.GetSecretValueInput{
		SecretId:     aws.String(r.SecretID),
		VersionStage: aws.String("AWSCURRENT")})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to get secret: %v", err))
		return "", err
	}

	return *result.SecretString, nil
}

func (a *AWSManager) PutSecret(r *PutRequest) error {
	_, err := a.client.PutSecretValue(context.TODO(), &sm.PutSecretValueInput{
		SecretId:     aws.String(r.SecretID),
		SecretString: aws.String(r.Token)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to put secret: %v", err))
		return err
	}

	return nil
}

func (a *AWSManager) CreateSecret(r *PutRequest) error {
	_, err := a.client.CreateSecret(context.TODO(), &sm.CreateSecretInput{
		Name:         aws.String(r.SecretID),
		SecretString: aws.String(r.Token),
	})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to create secret: %v", err))
		return err
	}

	return nil
}

func (a *AWSManager) ResolveSecretID(r *ResolveIDRequest) (string, error) {
	secretID := fmt.Sprintf("stackedtracker-oauth/%v", r.UserID)

	_, err := a.client.DescribeSecret(context.TODO(), &sm.DescribeSecretInput{SecretId: aws.String(secretID)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to resolve secret: %v", err))
		return "", err
	}

	return secretID, nil
}

// IsErrorResourceNotFound This function will unwrap a given error and check if
// it contains types.ResourceNotFoundException. This is an error type that indicates
// that our application tried to access a secret that does not exist. This is useful
// to decide if we should create the secret or not if it's some other error type.
func IsErrorResourceNotFound(err error) bool {
	var resourceNotFound *types.ResourceNotFoundException

	return errors.As(err, &resourceNotFound)
}
