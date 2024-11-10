package token

import (
	"app/internal/aws/secret"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"log/slog"
	"time"
)

type (
	// RetrieveRequest is the request struct for the RetrieveToken endpoint handler.
	// It contains the UserID for the token that needs to be retrieved.
	RetrieveRequest struct {
		UserID string `json:"user_id" binding:"required"`
	}

	// SaveRequest is the request struct for the SaveToken endpoint handler. It contains
	// the UserID, AccessToken, RefreshToken, and Expiry of the token that needs to be saved.
	SaveRequest struct {
		UserID       string    `json:"user_id" binding:"required"`
		AccessToken  string    `json:"access_token" binding:"required"`
		RefreshToken string    `json:"refresh_token" binding:"required"`
		Expiry       time.Time `json:"expiry" binding:"required"`
	}

	// Manager interface is the abstraction around behaviour to retrieve and
	// save tokens, which is required by the handler after a REST request for
	// each of those respective behaviours. It is a composition of the two
	// interfaces Retriever and Saver, which correspond to the rest.RetrieveToken
	// and rest.SaveToken endpoint handlers, respectfully.
	Manager interface {
		Retriever
		Saver
	}

	// Retriever interface defines the behaviour of retrieving a token from the
	// secret manager. It takes a RetrieveRequest struct pointer as an argument
	// and returns the token or an error.
	Retriever interface {
		RetrieveToken(r *RetrieveRequest) (*oauth2.Token, error)
	}

	// Saver interface defines the behaviour of saving a token to the secret manager.
	// It takes a SaveRequest struct pointer as an argument and returns an error.
	Saver interface {
		SaveToken(r *SaveRequest) error
	}
)

// OAuthManager is the implementation for the Manager interface. It is the
// implementation that the handler will use to call business logic after a REST
// request is received. It contains an aws.Manager interface as dependency as
// it depends on behaviour to store, retrieve and create secrets for the tokens.
type OAuthManager struct {
	sm secret.Manager
}

func NewOAuthManager(sm secret.Manager) *OAuthManager {
	return &OAuthManager{sm}
}

func (o *OAuthManager) RetrieveToken(r *RetrieveRequest) (*oauth2.Token, error) {
	secretID, err := o.sm.ResolveSecretID(&secret.ResolveIDRequest{
		Domain: "token",
		UserID: r.UserID})
	if err != nil {
		slog.Error(fmt.Sprintf("Could not retrieve token. Resolving SecretID failed: %v", err))
		return nil, err
	}

	secretStr, err := o.sm.GetSecret(&secret.GetRequest{
		SecretID: secretID})
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	if err = json.Unmarshal([]byte(secretStr), &token); err != nil {
		slog.Error(fmt.Sprintf("Unable to unmarshal secret JSON to oauth2.Token: %v", err))
		return nil, err
	}
	return &token, nil
}

func (o *OAuthManager) SaveToken(r *SaveRequest) error {
	tokenJSON, err := json.Marshal(oauth2.Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		Expiry:       r.Expiry})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to marshal oauth2.Token: %v", err))
		return err
	}

	secretID, err := o.sm.ResolveSecretID(&secret.ResolveIDRequest{
		Domain: "token",
		UserID: r.UserID})
	if err != nil {
		if secret.IsErrorResourceNotFound(err) {
			return o.sm.CreateSecret(&secret.PutRequest{
				SecretID: secretID,
				Token:    string(tokenJSON)})
		}
		return err
	}

	if err = o.sm.PutSecret(&secret.PutRequest{
		SecretID: secretID,
		Token:    string(tokenJSON)}); err != nil {
		return err
	}

	return nil
}
