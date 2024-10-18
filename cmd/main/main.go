package main

import (
	"app/internal/http"
	"app/internal/secret"
	"github.com/gin-gonic/gin"
	"log"
)

func main() {
	// Create services
	secretManagerService, err := secret.NewAWSService()
	if err != nil {
		log.Fatal(err)
	}

	saveSecretRequestService := http.SaveSecretRequestService{SecretManagerService: secretManagerService}
	loadSecretRequestService := http.LoadSecretRequestService{SecretManagerService: secretManagerService}

	// Initialize Gin Router
	r := gin.Default()

	// Define routes
	r.PUT("/token/save", saveSecretRequestService.TokenHandler)
	r.GET("/token/get", loadSecretRequestService.TokenHandler)

	// Run the Gin server
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to run server: ", err)
	}
}
