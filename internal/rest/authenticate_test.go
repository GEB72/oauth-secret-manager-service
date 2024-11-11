package rest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"testing"
)

type ParserStub struct {
	ParserFunc func(tokenString string) (*jwt.Token, error)
}

func (p *ParserStub) ParseJWT(value string) (*jwt.Token, error) {
	return p.ParserFunc(value)
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name        string
		stub        *ParserStub
		authHeader  string
		requestBody string
		wantStatus  int
		wantBody    gin.H
	}{
		{
			name: "AuthenticateSuccess",
			stub: &ParserStub{
				ParserFunc: func(tokenString string) (*jwt.Token, error) {
					return &jwt.Token{Valid: true, Claims: jwt.MapClaims{"sub": "userID"}}, nil
				},
			},
			authHeader:  "Bearer valid-token",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "AuthenticateInvalidRequestBody",
			authHeader:  "",
			requestBody: "{}",
			wantStatus:  http.StatusBadRequest,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
		{
			name:        "AuthenticateEmptyAuthorizationHeader",
			authHeader:  "",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusBadRequest,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
		{
			name:        "AuthenticateInvalidAuthorizationHeader",
			authHeader:  "InvalidFormat",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusBadRequest,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
		{
			name: "AuthenticateInvalidToken",
			stub: &ParserStub{
				ParserFunc: func(tokenString string) (*jwt.Token, error) {
					return &jwt.Token{Valid: false, Claims: jwt.MapClaims{"sub": "userID"}}, nil
				},
			},
			authHeader:  "Bearer valid-token",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusUnauthorized,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
		{
			name: "AuthenticateInvalidClaimsType",
			stub: &ParserStub{
				ParserFunc: func(tokenString string) (*jwt.Token, error) {
					return &jwt.Token{Valid: true}, nil
				},
			},
			authHeader:  "Bearer valid-token",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusUnauthorized,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
		{
			name: "AuthenticateUserIDMismatch",
			stub: &ParserStub{
				ParserFunc: func(tokenString string) (*jwt.Token, error) {
					return &jwt.Token{Valid: true, Claims: jwt.MapClaims{"sub": "wrongID"}}, nil
				},
			},
			authHeader:  "Bearer valid-token",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusUnauthorized,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := Authenticate(tt.stub)

			resp := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(resp)
			c.Request = httptest.NewRequest("POST", "/test", bytes.NewBufferString(tt.requestBody))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Request.Header.Set("Authorization", tt.authHeader)

			handler(c)
			if resp.Code != tt.wantStatus {
				t.Errorf("RetrieveToken() status = %v, wantStatus = %v", resp.Code, tt.wantStatus)
			}
			for key, value := range tt.wantBody {
				if getValueFromResponse(t, resp.Body, key) != value {
					t.Errorf("RetrieveToken() body = %v, wantBody = %v", resp.Body.String(), tt.wantBody)
					break
				}
			}
		})
	}
}

type KeyManagerStub struct {
	KeyFunc func() ([]byte, error)
}

func (k *KeyManagerStub) GetPublicKey() ([]byte, error) {
	return k.KeyFunc()
}

func TestJWTParser_Parse(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name        string
		stub        *KeyManagerStub
		tokenString string
		wantErr     bool
	}{
		{
			name: "ParseSuccess",
			stub: &KeyManagerStub{KeyFunc: func() ([]byte, error) {
				return x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			}},
			tokenString: generateTestToken(privateKey),
			wantErr:     false,
		},
		{
			name: "ParseWrongPublicKey",
			stub: &KeyManagerStub{KeyFunc: func() ([]byte, error) {
				return x509.MarshalPKIXPublicKey(&otherPrivateKey.PublicKey)
			}},
			tokenString: generateTestToken(privateKey),
			wantErr:     true,
		},
		{
			name: "ParseWrongPrivateKey",
			stub: &KeyManagerStub{KeyFunc: func() ([]byte, error) {
				return x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			}},
			tokenString: generateTestToken(otherPrivateKey),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser, err := NewJWTParser(tt.stub)

			_, err = parser.ParseJWT(tt.tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseJWT() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func generateTestToken(privateKey *rsa.PrivateKey) string {
	claims := jwt.MapClaims{"sub": "1"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, _ := token.SignedString(privateKey)

	return tokenString
}
