package secretmanager

import (
	"golang.org/x/oauth2"
)

type ServiceInterface interface {
	LoadSecret(secretName string) (*oauth2.Token, error)
	StoreSecret(secretName string, token *oauth2.Token) error
}
