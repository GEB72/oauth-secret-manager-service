package rest

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"testing"
)

type ParserStub struct {
	ParserFunc func(tokenString string) (*jwt.Token, error)
}

func (p *ParserStub) Parse(value string) (*jwt.Token, error) {
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
			wantStatus:  http.StatusUnauthorized,
			wantBody:    gin.H{"Error": "Could not authenticate user"},
		},
		{
			name:        "AuthenticateInvalidAuthorizationHeader",
			authHeader:  "InvalidFormat",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusUnauthorized,
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

func TestJWTParser_Parse(t *testing.T) {
	tests := []struct {
		name          string
		signingMethod jwt.SigningMethod
		secretKey     []byte
		tokenString   string
		wantErr       bool
	}{
		{
			name:          "ParseSuccess",
			signingMethod: jwt.SigningMethodHS256,
			secretKey:     []byte("your-secret-key"),
			tokenString:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.hZXAt4uakIsbrWavNREXoiEAnd4oUkCGS2OrzUPocXw",
			wantErr:       false,
		},
		{
			name:          "ParseInvalidSigningMethod",
			signingMethod: jwt.SigningMethodES256,
			secretKey:     []byte("your-secret-key"),
			tokenString:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.hZXAt4uakIsbrWavNREXoiEAnd4oUkCGS2OrzUPocXw",
			wantErr:       true,
		},
		{
			name:          "ParseInvalidSecretKey",
			signingMethod: jwt.SigningMethodES256,
			secretKey:     []byte("wrong-secret-key"),
			tokenString:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.hZXAt4uakIsbrWavNREXoiEAnd4oUkCGS2OrzUPocXw",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &JWTParser{
				signingMethod: tt.signingMethod,
				secretKey:     tt.secretKey,
			}

			_, err := parser.Parse(tt.tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
