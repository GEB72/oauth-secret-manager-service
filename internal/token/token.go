package token

import (
	"app/api"
	"app/env"
	"app/internal/secret"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"log/slog"
)

type (
	Retriever interface {
		RetrieveToken(r *api.RetrieveTokenRequest) (*oauth2.Token, error)
	}

	Saver interface {
		SaveToken(r *api.SaveTokenRequest) error
	}

	// ApiRetriever is the implementation for the Retriever interface.
	// It contains secret.IDResolver and secret.Getter interfaces as dependencies
	// to retrieve secrets for the tokens.
	ApiRetriever struct {
		Env env.AwsVars
		Res secret.IDResolver
		Get secret.Getter
	}

	// ApiSaver is the implementation for the Saver interface.
	// It contains secret.IDResolver, secret.Putter and secret.Creator interfaces as dependencies
	// to create and store secrets for the tokens.
	ApiSaver struct {
		Res secret.IDResolver
		Put secret.Putter
		Ctr secret.Creator
	}
)

func (rt *ApiRetriever) RetrieveToken(r *api.RetrieveTokenRequest) (*oauth2.Token, error) {
	secretID, err := rt.Res.ResolveSecretID(&api.ResolveSecretRequest{
		RootDomain: rt.Env.SmsRootDomain,
		Domain:     "token",
		UserID:     r.UserID})
	if err != nil {
		slog.Error(fmt.Sprintf("Could not retrieve token. Resolving SecretID failed: %v", err))
		return nil, err
	}

	secretStr, err := rt.Get.GetSecret(&api.GetSecretRequest{SecretID: secretID})
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

func (sv *ApiSaver) SaveToken(r *api.SaveTokenRequest) error {
	tokenJSON, err := json.Marshal(oauth2.Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		Expiry:       r.Expiry})
	if err != nil {
		slog.Error(fmt.Sprintf("Unable to marshal oauth2.Token: %v", err))
		return err
	}

	secretID, err := sv.Res.ResolveSecretID(&api.ResolveSecretRequest{
		Domain: "token",
		UserID: r.UserID})
	if err != nil {
		if secret.IsErrorResourceNotFound(err) {
			return sv.Ctr.CreateSecret(&api.CreateSecretRequest{
				SecretID: secretID,
				Token:    string(tokenJSON)})
		}
		return err
	}

	return sv.Put.PutSecret(&api.PutSecretRequest{SecretID: secretID, Token: string(tokenJSON)})
}
