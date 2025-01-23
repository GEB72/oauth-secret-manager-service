package secret

import (
	"app/api"
	"context"
	"errors"
	"fmt"
	aw "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"log/slog"
)

type (
	// Getter interface defines the behaviour of getting a secret from the secret manager.
	// It takes a GetRequest struct pointer as an argument and returns the secret value
	// or an error.
	Getter interface {
		GetSecret(r *api.GetSecretRequest) (string, error)
	}

	// Putter interface defines the behaviour of putting a secret into the secret manager.
	// It takes a PutRequest struct pointer as an argument and returns an error.
	Putter interface {
		PutSecret(r *api.PutSecretRequest) error
	}

	// Creator interface defines the behaviour of creating a secret in the secret manager.
	// It takes a PutRequest struct pointer as an argument and returns an error.
	Creator interface {
		CreateSecret(r *api.CreateSecretRequest) error
	}

	// IDResolver interface defines the behaviour of resolving the secret ID from the user ID
	// and the domain which together with the root domain will form the secret ID. It takes
	// a ResolveIDRequest struct pointer as an argument and returns the secret ID or an error.
	IDResolver interface {
		ResolveSecretID(r *api.ResolveSecretRequest) (string, error)
	}

	// Client interface define an abstraction/wrapper around secretsmanager.Client.
	// This is useful so that our secret.AWSManager can depend on an abstraction such that the
	// behaviour can be easily stubbed out for testing.
	Client interface {
		GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (
			*sm.GetSecretValueOutput, error)
		PutSecretValue(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (
			*sm.PutSecretValueOutput, error)
		CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (
			*sm.CreateSecretOutput, error)
		DescribeSecret(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (
			*sm.DescribeSecretOutput, error)
	}

	AWSManager struct {
		AWSGetter
		AWSPutter
		AWSCreator
		AWSResolver
	}

	AWSGetter struct {
		Client Client
	}

	AWSPutter struct {
		Client Client
	}

	AWSCreator struct {
		Client Client
	}

	AWSResolver struct {
		Client Client
	}
)

func NewClient() (*sm.Client, error) {
	conf, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to load SDK config: %v", err))
		return nil, err
	}

	return sm.NewFromConfig(conf), nil
}

func (gt *AWSGetter) GetSecret(r *api.GetSecretRequest) (string, error) {
	result, err := gt.Client.GetSecretValue(context.TODO(), &sm.GetSecretValueInput{
		SecretId: aw.String(r.SecretID)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to gt secret: %v", err))
		return "", err
	}

	return *result.SecretString, nil
}

func (pt *AWSPutter) PutSecret(r *api.PutSecretRequest) error {
	_, err := pt.Client.PutSecretValue(context.TODO(), &sm.PutSecretValueInput{
		SecretId:     aw.String(r.SecretID),
		SecretString: aw.String(r.Token)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to pt secret: %v", err))
		return err
	}

	return nil
}

func (ct *AWSCreator) CreateSecret(r *api.CreateSecretRequest) error {
	_, err := ct.Client.CreateSecret(context.TODO(), &sm.CreateSecretInput{
		Name:         aw.String(r.SecretID),
		SecretString: aw.String(r.Token)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to create secret: %v", err))
		return err
	}

	return nil
}

func (rs *AWSResolver) ResolveSecretID(r *api.ResolveSecretRequest) (string, error) {
	secretID := fmt.Sprintf("%v/%v/%v", r.RootDomain, r.Domain, r.UserID)
	_, err := rs.Client.DescribeSecret(context.TODO(), &sm.DescribeSecretInput{SecretId: aw.String(secretID)})
	if err != nil {
		slog.Info(fmt.Sprintf("Unable to resolve secret: %v", err))
		return secretID, err
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
