package main

import (
	"app/internal/aws/key"
	"app/internal/aws/secret"
	"app/internal/rest"
	"app/internal/token"
	"fmt"
	"github.com/gin-gonic/gin"
	"log/slog"
)

func main() {
	// Create dependencies
	sm, err := secret.NewSecretManager()
	if err != nil {
		panic(fmt.Sprintf("Could not create AWS Secret Manager: %v", err))
	}
	tm := token.NewOAuthManager(sm)
	km, err := key.NewKeyManager()
	if err != nil {
		panic(fmt.Sprintf("Could not create AWS Key Manager: %v", err))
	}
	psr, err := rest.NewJWTParser(km)
	if err != nil {
		panic(fmt.Sprintf("Could not create JWT Parser: %v", err))
	}

	// Create router
	r := GinRouter{TokenManager: tm, Parser: psr}

	// Run the server
	r.StartServer()
}

type GinRouter struct {
	TokenManager token.Manager
	Parser       rest.Parser
}

// StartServer defines a Gin router with /token/save and /token/get endpoints. It also
// contains the gin.Recovery and Authenticate middleware that recover the server from
// panic calls and authenticate userID's in requests, respectively.
func (g GinRouter) StartServer() *gin.Engine {
	// Create router
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(rest.Authenticate(g.Parser))

	// Define routes
	r.PUT("/token/save", rest.SaveTokenHandler(g.TokenManager))
	r.GET("/token/get", rest.RetrieveTokenHandler(g.TokenManager))

	// Run the server
	slog.Info("Starting Server!")
	if err := r.Run(":8080"); err != nil {
		slog.Error(fmt.Sprintf("Server has died! %v", err))
	}

	return r
}
