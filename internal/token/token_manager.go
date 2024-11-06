package token

import (
	"app/internal/secret"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"log/slog"
	"time"
)

// These struct types define the structure for incoming requests to the
// Manager. They are also used by the rest.RetrieveToken and rest.SaveToken
// handlers to bind the request body JSON to a struct with the "required"
// value ensuring that every field is non-empty.
type (
	RetrieveRequest struct {
		UserID string `json:"user_id" binding:"required"`
	}

	SaveRequest struct {
		UserID       string    `json:"user_id" binding:"required"`
		AccessToken  string    `json:"access_token" binding:"required"`
		RefreshToken string    `json:"refresh_token" binding:"required"`
		Expiry       time.Time `json:"expiry" binding:"required"`
	}
)

// Manager interface is the abstraction around behaviour to retrieve and
// save tokens, which is required by the handler after a REST request for
// each of those respective behaviours. It is a composition of the two
// interfaces Retriever and Saver, which correspond to the rest.RetrieveToken
// and rest.SaveToken endpoint handlers, respectfully.
type (
	Manager interface {
		Retriever
		Saver
	}

	Retriever interface {
		RetrieveToken(r RetrieveRequest) (*oauth2.Token, error)
	}

	Saver interface {
		SaveToken(r SaveRequest) error
	}
)

// OAuthManager is the implementation for the Manager interface. It is the
// implementation that the handler will use to call business logic after a REST
// request is received. It contains a secret.Manager interface as dependency as
// it depends on behaviour to store, retrieve and create secrets for the tokens.
type OAuthManager struct {
	sm secret.Manager
}

func NewOAuthManager(sm secret.Manager) OAuthManager {
	return OAuthManager{sm}
}

func (o OAuthManager) RetrieveToken(r RetrieveRequest) (*oauth2.Token, error) {
	secretID, err := o.sm.ResolveSecretID(&secret.ResolveIDRequest{UserID: r.UserID})
	if err != nil {
		return nil, err
	}

	secretStr, err := o.sm.GetSecret(&secret.GetRequest{SecretID: secretID})
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

func (o OAuthManager) SaveToken(r SaveRequest) error {
	tokenJSON, err := json.Marshal(oauth2.Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		Expiry:       r.Expiry})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to marshal oauth2.Token: %v", err))
		return err
	}

	secretID, err := o.sm.ResolveSecretID(&secret.ResolveIDRequest{UserID: r.UserID})
	if err != nil {
		if secret.IsErrorResourceNotFound(err) {
			return o.sm.CreateSecret(&secret.PutRequest{SecretID: secretID, Token: string(tokenJSON)})
		}
		return err
	}

	if err = o.sm.PutSecret(&secret.PutRequest{SecretID: secretID, Token: string(tokenJSON)}); err != nil {
		return err
	}

	return nil
}
