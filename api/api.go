package api

import "time"

type (
	// RetrieveTokenRequest is the request struct for the RetrieveToken endpoint handler.
	// It contains the UserID for the token that needs to be retrieved.
	RetrieveTokenRequest struct {
		UserID string `json:"user_id" binding:"required"`
	}

	// SaveTokenRequest is the request struct for the SaveToken endpoint handler. It contains
	// the UserID, AccessToken, RefreshToken, and Expiry of the token that needs to be saved.
	SaveTokenRequest struct {
		UserID       string    `json:"user_id" binding:"required"`
		AccessToken  string    `json:"access_token" binding:"required"`
		RefreshToken string    `json:"refresh_token" binding:"required"`
		Expiry       time.Time `json:"expiry" binding:"required"`
	}

	GetSecretRequest struct {
		SecretID string
	}

	PutSecretRequest struct {
		SecretID string
		Token    string
	}

	CreateSecretRequest struct {
		SecretID string
		Token    string
	}

	ResolveSecretRequest struct {
		RootDomain string
		Domain     string
		UserID     string
	}
)
