package user

import (
	"crypto"
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
		var req struct {
			UserID string `json:"user_id" binding:"required"`
		}
		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			slog.Error(err.Error())
			c.AbortWithStatusJSON(http.StatusBadRequest, errorBody)
			return
		}

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

		token, err := p.Parse(tokenString)
		if err != nil || !token.Valid {
			slog.Error(fmt.Sprintf("Invalid token or parsing error: %s", err))
			c.AbortWithStatusJSON(http.StatusBadRequest, errorBody)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			slog.Error("Could not extract userID from token")
			c.AbortWithStatusJSON(http.StatusBadRequest, errorBody)
			return
		}

		if req.UserID != claims["sub"] {
			slog.Error("Invalid userID")
			c.AbortWithStatusJSON(http.StatusBadRequest, errorBody)
			return
		}

		c.Next()
	}
}

type (
	Parser interface {
		Parse(tokenString string) (*jwt.Token, error)
	}

	JWTParser struct {
		signingMethod jwt.SigningMethod
		secretKey     []byte
	}
)

func NewJWTParser() *JWTParser {
	return &JWTParser{
		signingMethod: &jwt.SigningMethodHMAC{Name: "HS256", Hash: crypto.SHA256},
		secretKey:     []byte("your-secret-key"),
	}
}

func (j *JWTParser) Parse(tokenString string) (*jwt.Token, error) {
	validateSigningMethod := func(token *jwt.Token) (interface{}, error) {
		if !reflect.DeepEqual(token.Method, j.signingMethod) {
			err := fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			slog.Error(err.Error())
			return nil, err
		}

		return []byte("your-secret-key"), nil
	}
	return jwt.Parse(tokenString, validateSigningMethod)
}
