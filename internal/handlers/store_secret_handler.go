package handlers

import (
	"app/internal/services/secretmanager"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

type StoreSecretHandler struct {
	SecretManagerService secretmanager.ServiceInterface
}

func NewStoreSecretHandler(secretManagerService secretmanager.ServiceInterface) *StoreSecretHandler {
	return &StoreSecretHandler{SecretManagerService: secretManagerService}
}

func (handler *StoreSecretHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// get the token from the request body
	var token oauth2.Token
	if err := json.NewDecoder(request.Body).Decode(&token); err != nil {
		http.Error(writer, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// defer closing the request body, error if failed
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			http.Error(writer, "Failed to close request body", http.StatusInternalServerError)
		}
	}(request.Body)

	// get the secret name from the query parameters
	secretName := request.URL.Query().Get("secretName")
	if secretName == "" {
		http.Error(writer, "Missing secretName parameter", http.StatusBadRequest)
		return
	}

	// store the secret
	if err := handler.SecretManagerService.StoreSecret(secretName, &token); err != nil {
		http.Error(writer, fmt.Sprintf("Failed to store secret: %v", err), http.StatusInternalServerError)
		return
	}

	// write status OK response
	writer.WriteHeader(http.StatusOK)
}
