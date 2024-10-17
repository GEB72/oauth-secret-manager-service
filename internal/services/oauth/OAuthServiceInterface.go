package oauth

import (
	"net/http"
)

type ServiceInterface interface {
	CreateClientFromToken() (*http.Client, error)
}
