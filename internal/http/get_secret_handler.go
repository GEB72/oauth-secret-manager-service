package http

import (
	"app/internal/secret"
	"github.com/gin-gonic/gin"
)

type GetTokenResponse struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type LoadSecretRequestService struct {
	SecretManagerService secret.SecretManager
}

func (h *LoadSecretRequestService) TokenHandler(c *gin.Context) {
}
