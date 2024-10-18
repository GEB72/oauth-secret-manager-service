package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.org/x/oauth2"
)

type AWSSecretManagerService struct {
	secretsClient *secretsmanager.Client
}

func NewAWSService() (*AWSSecretManagerService, error) {
	// get default config
	defaultConfig, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-north-1"))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS SDK config: %v", err)
	}

	// create  secret manager client
	secretsClient := secretsmanager.NewFromConfig(defaultConfig)

	// create and return object
	return &AWSSecretManagerService{secretsClient}, nil
}

func (s AWSSecretManagerService) GetSecret(secretName string) (*oauth2.Token, error) {
	// populate secret fields
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}

	// get value from secret
	result, err := s.secretsClient.GetSecretValue(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain aws secret from http client: %v", err)
	} else if *result.SecretString == "{\"empty\":\"\"}" {
		return nil, nil
	}

	// convert secret JSON to token
	var token oauth2.Token
	if err := json.Unmarshal([]byte(*result.SecretString), &token); err != nil {
		return nil, fmt.Errorf("unable to unmarshal secret JSON to oauth2.Token: %v", err)
	}

	return &token, nil
}

func (s AWSSecretManagerService) SaveSecret(secretName string, token *oauth2.Token) error {
	// Convert token data to JSON
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("unable to marshal token data to JSON: %v", err)
	}

	// Create the input for updating the secret
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(string(tokenJSON)),
	}

	// Store or update the secret
	_, err = s.secretsClient.PutSecretValue(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("unable to store secret: %v", err)
	}

	return nil
}
