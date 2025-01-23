package main

import (
	"app/env"
	"app/internal/key"
	"app/internal/rest"
	"app/internal/secret"
	"app/internal/token"
	"fmt"
	"github.com/gin-gonic/gin"
	"log/slog"
)

func main() {
	vars, err := env.GetAwsVars()
	if err != nil {
		slog.Error("Server not started, could not get env vars", "error", err.Error())
		return
	}

	scl, err := secret.NewClient()
	if err != nil {
		slog.Error("Server not started, could not get secret client", "error", err.Error())
		return
	}

	kcl, err := key.NewClient()
	if err != nil {
		slog.Error("Server not started, could not get key client", "error", err.Error())
		return
	}

	psr, err := rest.NewJWTParser(&key.AwsGetter{Client: kcl, KeyID: vars.KmsKeyID})
	if err != nil {
		slog.Error("Server not started, could not create JWT Parser", "error", err.Error())
	}

	mgr := secret.AWSManager{
		AWSGetter:   secret.AWSGetter{Client: scl},
		AWSPutter:   secret.AWSPutter{Client: scl},
		AWSCreator:  secret.AWSCreator{Client: scl},
		AWSResolver: secret.AWSResolver{Client: scl},
	}

	svr := token.ApiSaver{
		Res: &mgr.AWSResolver,
		Put: &mgr.AWSPutter,
		Ctr: &mgr.AWSCreator,
	}

	rtr := token.ApiRetriever{
		Res: &mgr.AWSResolver,
		Get: &mgr,
	}

	// Create router
	r := GinRouter{Saver: &svr, Retriever: &rtr, Parser: psr}

	// Run the server
	r.StartServer()
}

type GinRouter struct {
	Saver     token.Saver
	Retriever token.Retriever
	Parser    rest.Parser
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
	r.PUT("/token/save", rest.SaveTokenHandler(g.Saver))
	r.GET("/token/get", rest.RetrieveTokenHandler(g.Retriever))

	// Run the server
	slog.Info("Starting Server!")
	if err := r.Run(":8080"); err != nil {
		slog.Error(fmt.Sprintf("Server has died! %v", err))
	}

	return r
}
