package secret

import (
	"golang.org/x/oauth2"
)

type SecretManager interface {
	GetSecret(secretName string) (*oauth2.Token, error)
	SaveSecret(secretName string, token *oauth2.Token) error
}
