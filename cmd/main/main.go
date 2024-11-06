package main

import (
	"app/internal/rest"
	"app/internal/secret"
	"app/internal/token"
	"fmt"
	"github.com/gin-gonic/gin"
	"log/slog"
)

func main() {
	// Create dependencies
	sm, err := secret.NewAWSManager()
	if err != nil {
		slog.Error(fmt.Sprintf("Could not create AWS Secret Manager: %v", err))
	}
	tm := token.NewOAuthManager(sm)

	// Create router
	r := NewRouter(tm)

	// Run the server
	slog.Info("Starting Server!")
	if err := r.Run(":8080"); err != nil {
		slog.Error(fmt.Sprintf("Server has died! %v", err))
	}
}

// NewRouter defines a Gin router with /token/save and /token/get endpoints. It also
// contains the gin.Recovery and Authenticate middleware that recover the server from
// panic calls and authenticate userID's in requests, respectively.
func NewRouter(tm token.Manager) *gin.Engine {
	// Create router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(rest.Authenticate(rest.NewJWTParser()))

	// Define routes
	router.PUT("/token/save", rest.SaveTokenHandler(tm))
	router.GET("/token/get", rest.RetrieveTokenHandler(tm))

	return router
}
