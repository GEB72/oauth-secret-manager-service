package rest

import (
	"app/internal/token"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type SaverRetrieverStub struct {
	RetrieveTokenFunc func(token.RetrieveRequest) (*oauth2.Token, error)
	SaveTokenFunc     func(token.SaveRequest) error
}

func (s *SaverRetrieverStub) RetrieveToken(req token.RetrieveRequest) (*oauth2.Token, error) {
	return s.RetrieveTokenFunc(req)
}

func (s *SaverRetrieverStub) SaveToken(req token.SaveRequest) error {
	return s.SaveTokenFunc(req)
}

func TestRetrieveTokenHandler(t *testing.T) {
	tests := []struct {
		name          string
		retrieverStub func(token.RetrieveRequest) (*oauth2.Token, error)
		requestBody   string
		wantStatus    int
		wantBody      map[string]interface{}
	}{
		{
			name: "RetrieveTokenSuccess",
			retrieverStub: func(req token.RetrieveRequest) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token",
					RefreshToken: "refresh_token",
				}, nil
			},
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusOK,
			wantBody: gin.H{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		},
		{
			name:        "RetrieveTokenInvalidRequestBody",
			requestBody: `{"user": "userID"}`,
			wantStatus:  http.StatusBadRequest,
			wantBody:    gin.H{"Error": "Could not retrieve token"},
		},
		{
			name: "RetrieveTokenRetrieverError",
			retrieverStub: func(req token.RetrieveRequest) (*oauth2.Token, error) {
				return nil, errors.New("server error")
			},
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusInternalServerError,
			wantBody:    gin.H{"Error": "Could not retrieve token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RetrieveTokenHandler(&SaverRetrieverStub{RetrieveTokenFunc: tt.retrieverStub})

			resp := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(resp)
			c.Request = httptest.NewRequest("POST", "/token/get", bytes.NewBufferString(tt.requestBody))
			c.Request.Header.Set("Content-Type", "application/json")

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

func TestSaveTokenHandler(t *testing.T) {
	tests := []struct {
		name        string
		saverStub   func(token.SaveRequest) error
		requestBody string
		wantStatus  int
		wantBody    map[string]interface{}
	}{
		{
			name: "SaveTokenSuccessful",
			saverStub: func(req token.SaveRequest) error {
				return nil
			},
			requestBody: fmt.Sprintf(`{
				"user_id":       "userID", 
				"access_token":  "access_token", 
				"refresh_token": "refresh_token", 
				"expiry":        "%s"}`, time.Now().Format(time.RFC3339)),
			wantStatus: http.StatusOK,
			wantBody:   gin.H{"Message": "Token saved successfully"},
		},
		{
			name:        "SaveTokenInvalidRequestBody",
			requestBody: `{"user_id": "userID"}`,
			wantStatus:  http.StatusBadRequest,
			wantBody:    gin.H{"Error": "Could not save token"},
		},
		{
			name: "SaveTokenSaverError",
			saverStub: func(req token.SaveRequest) error {
				return errors.New("server error")
			},
			requestBody: fmt.Sprintf(`{
				"user_id":       "userID", 
				"access_token":  "access_token", 
				"refresh_token": "refresh_token", 
				"expiry":        "%s"}`, time.Now().Format(time.RFC3339)),
			wantStatus: http.StatusInternalServerError,
			wantBody:   gin.H{"Error": "Could not save token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := SaveTokenHandler(&SaverRetrieverStub{SaveTokenFunc: tt.saverStub})

			resp := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(resp)
			c.Request = httptest.NewRequest("POST", "/token/save", bytes.NewBufferString(tt.requestBody))
			c.Request.Header.Set("Content-Type", "application/json")

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

func getValueFromResponse(t *testing.T, body *bytes.Buffer, key string) any {
	var responseBody gin.H
	if err := json.Unmarshal(body.Bytes(), &responseBody); err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	return responseBody[key]
}
