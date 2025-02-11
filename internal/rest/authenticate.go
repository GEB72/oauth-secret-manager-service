package rest

import (
	"app/internal/key"
	"crypto"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
)

// Authenticate is a middleware that will authenticate a userID before every request.
// If authentication fails, then the pending handlers are not executed, and the request
// is scrapped with status code http.StatusUnauthorized. The function checks if the
// headers are set correctly, with the right signing method for the JWT and that the
// UserID from the decrypted JWT matches the UserID in the request body.
func Authenticate(p Parser) gin.HandlerFunc {
	errorBody := gin.H{"Error": "Could not authenticate user"}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			slog.Error("Authorization header is empty")
			c.AbortWithStatusJSON(http.StatusBadRequest, errorBody)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if !strings.Contains(authHeader, "Bearer ") || tokenString == "" {
			slog.Error("Invalid authorization header format")
			c.AbortWithStatusJSON(http.StatusBadRequest, errorBody)
			return
		}

		token, err := p.ParseJWT(tokenString)
		if err != nil || !token.Valid {
			slog.Error(fmt.Sprintf("Invalid token or parsing error: %s", err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorBody)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			slog.Error("Could not extract userID from token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorBody)
			return
		}

		userID, ok := claims["sub"]
		if !ok || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, errorBody)
			return
		}

		c.Set("user_id", claims["sub"])
		c.Next()
	}
}

// Parser is an interface that defines the Parse method, which will parse a token
// string and return a jwt.Token or an error. It is used as a wrapper around the
// jwt.Parse method to allow for easier testing and stubbing.
type Parser interface {
	ParseJWT(tokenString string) (*jwt.Token, error)
}

// JWTParser is an implementation of the Parser interface. It contains the public key
// and signing method for the JWT token. It is used to parse and validate the token
// before authenticating the user.
type JWTParser struct {
	signingMethod jwt.SigningMethod
	pubKey        *rsa.PublicKey
}

func NewJWTParser(km key.Getter) (*JWTParser, error) {
	pubKeyBytes, err := km.GetPublicKey()
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &JWTParser{
		signingMethod: &jwt.SigningMethodRSA{Name: "RS256", Hash: crypto.SHA256},
		pubKey:        pubKey,
	}, nil
}

func (j *JWTParser) ParseJWT(tokenString string) (*jwt.Token, error) {
	validateSigningMethod := func(token *jwt.Token) (interface{}, error) {
		if !reflect.DeepEqual(token.Method, j.signingMethod) {
			err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			slog.Error(err.Error())
			return nil, err
		}

		return j.pubKey, nil
	}
	return jwt.Parse(tokenString, validateSigningMethod)
}
