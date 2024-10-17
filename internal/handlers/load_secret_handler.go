package handlers

import (
	"app/internal/services/secretmanager"
	"encoding/json"
	"fmt"
	"net/http"
)

type LoadSecretHandler struct {
	SecretManagerService secretmanager.ServiceInterface
}

func NewLoadSecretHandler(secretManagerService secretmanager.ServiceInterface) *LoadSecretHandler {
	return &LoadSecretHandler{SecretManagerService: secretManagerService}
}

func (handler *LoadSecretHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// get the secret name from the query parameters
	secretName := request.URL.Query().Get("secretName")
	if secretName == "" {
		http.Error(writer, "Missing secretName parameter", http.StatusBadRequest)
		return
	}

	// load the secret from the secret manager, error if failed
	token, err := handler.SecretManagerService.LoadSecret(secretName)
	if err != nil {
		http.Error(writer, fmt.Sprintf("Failed to load secret: %v", err), http.StatusInternalServerError)
		return
	} else if token == nil {
		http.Error(writer, "Secret not found", http.StatusNotFound)
		return
	}

	// write the token as JSON response
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(token); err != nil {
		http.Error(writer, "Failed to encode response", http.StatusInternalServerError)
	}
}
