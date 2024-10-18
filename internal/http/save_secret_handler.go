package http

import (
	"app/internal/secret"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

type SaveTokenRequest struct {
	UserID       string    `json:"user_id" binding:"required"`
	AccessToken  string    `json:"access_token" binding:"required"`
	RefreshToken string    `json:"refresh_token" binding:"required"`
	Expiry       time.Time `json:"expiry" binding:"required"`
}

type SaveSecretRequestService struct {
	SecretManagerService secret.SecretManager
}

func (h SaveSecretRequestService) TokenHandler(c *gin.Context) {
	var req SaveTokenRequest

	// Bind JSON request to struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create or update the token in Secrets Manager
	token := oauth2.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		Expiry:       req.Expiry,
	}

	// TODO: Implement proper secret name based on UserID
	err := h.SecretManagerService.SaveSecret("stackedtracker-oauth", &token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save token"})
		return
	}

	// Respond with success
	c.JSON(http.StatusOK, gin.H{"message": "Token saved successfully"})
}
