package secret

import (
	"app/internal/aws"
	"context"
	"errors"
	"fmt"
	aw "github.com/aws/aws-sdk-go-v2/aws"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"log/slog"
	"os"
)

type (
	// GetRequest A request struct for obtaining secrets from the secret manager. It
	// contains the domain and the user ID which together with the root domain will
	// form the secret ID.
	GetRequest struct {
		SecretID string
	}

	// PutRequest A request struct for putting secrets into the secret manager. It
	// contains the domain and the user ID which together with the root domain will
	// form the secret ID. It also contains the token which is the secret value.
	PutRequest struct {
		SecretID string
		Token    string
	}

	// ResolveIDRequest A request struct for resolving the secret ID from the user ID
	// and the domain which together with the root domain will form the secret ID.
	ResolveIDRequest struct {
		Domain string
		UserID string
	}

	// Manager interface is a composition of four other interfaces that all specify
	// a behaviour that our secret manager implementation should implement. They
	// take the request struct pointers defined below as arguments.
	Manager interface {
		Getter
		Putter
		Creator
		IDResolver
	}

	// Getter interface defines the behaviour of getting a secret from the secret manager.
	// It takes a GetRequest struct pointer as an argument and returns the secret value
	// or an error.
	Getter interface {
		GetSecret(r *GetRequest) (string, error)
	}

	// Putter interface defines the behaviour of putting a secret into the secret manager.
	// It takes a PutRequest struct pointer as an argument and returns an error.
	Putter interface {
		PutSecret(r *PutRequest) error
	}

	// Creator interface defines the behaviour of creating a secret in the secret manager.
	// It takes a PutRequest struct pointer as an argument and returns an error.
	Creator interface {
		CreateSecret(r *PutRequest) error
	}

	// IDResolver interface defines the behaviour of resolving the secret ID from the user ID
	// and the domain which together with the root domain will form the secret ID. It takes
	// a ResolveIDRequest struct pointer as an argument and returns the secret ID or an error.
	IDResolver interface {
		ResolveSecretID(r *ResolveIDRequest) (string, error)
	}
)

// AWSManager struct is an implementation of the Manager interface. It contains the
// SecretClient wrapper for testing purposes. It's constructor will set the implementation
// of the wrapper to the real secretsmanager.Client from the AWS SDK.
type AWSManager struct {
	client     aws.SecretClient
	rootDomain string
}

func NewSecretManager() (*AWSManager, error) {
	cfg, err := aws.GetConfig()
	if err != nil {
		return nil, err
	}

	rootDomain := os.Getenv("SMS_ROOT_DOMAIN")
	if rootDomain == "" {
		return nil, fmt.Errorf("SMS_ROOT_DOMAIN environment variable not set")
	}

	return &AWSManager{
		client:     sm.NewFromConfig(*cfg),
		rootDomain: rootDomain,
	}, nil
}

func (m *AWSManager) GetSecret(r *GetRequest) (string, error) {
	result, err := m.client.GetSecretValue(context.TODO(), &sm.GetSecretValueInput{
		SecretId: aw.String(r.SecretID)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to get secret: %v", err))
		return "", err
	}

	return *result.SecretString, nil
}

func (m *AWSManager) PutSecret(r *PutRequest) error {
	_, err := m.client.PutSecretValue(context.TODO(), &sm.PutSecretValueInput{
		SecretId:     aw.String(r.SecretID),
		SecretString: aw.String(r.Token)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to put secret: %v", err))
		return err
	}

	return nil
}

func (m *AWSManager) CreateSecret(r *PutRequest) error {
	_, err := m.client.CreateSecret(context.TODO(), &sm.CreateSecretInput{
		Name:         aw.String(r.SecretID),
		SecretString: aw.String(r.Token)})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to create secret: %v", err))
		return err
	}

	return nil
}

func (m *AWSManager) ResolveSecretID(r *ResolveIDRequest) (string, error) {
	secretID := fmt.Sprintf("%v/%v/%v", m.rootDomain, r.Domain, r.UserID)
	_, err := m.client.DescribeSecret(context.TODO(), &sm.DescribeSecretInput{SecretId: aw.String(secretID)})
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
