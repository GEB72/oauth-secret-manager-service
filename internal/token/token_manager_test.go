package token

import (
	"app/internal/secret"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"golang.org/x/oauth2"
	"testing"
)

type SecretManagerStub struct {
	ResolveSecretIDFunc func(request *secret.ResolveIDRequest) (string, error)
	GetSecretFunc       func(request *secret.GetRequest) (string, error)
	PutSecretFunc       func(request *secret.PutRequest) error
	CreateSecretFunc    func(request *secret.PutRequest) error
}

func (s *SecretManagerStub) ResolveSecretID(request *secret.ResolveIDRequest) (string, error) {
	return s.ResolveSecretIDFunc(request)
}

func (s *SecretManagerStub) GetSecret(request *secret.GetRequest) (string, error) {
	return s.GetSecretFunc(request)
}

func (s *SecretManagerStub) PutSecret(request *secret.PutRequest) error {
	return s.PutSecretFunc(request)
}

func (s *SecretManagerStub) CreateSecret(request *secret.PutRequest) error {
	return s.CreateSecretFunc(request)
}

func TestOAuthManager_Retrieve(t *testing.T) {
	tests := []struct {
		name    string
		stub    *SecretManagerStub
		request RetrieveRequest
		want    *oauth2.Token
		wantErr bool
	}{
		{
			name: "RetrieveTokenSuccess",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "secretID", nil
				},
				GetSecretFunc: func(request *secret.GetRequest) (string, error) {
					return `{"access_token":  "access_token", 
							 "token_type":    "Bearer",
							 "refresh_token": "refresh_token"}`, nil
				},
			},
			request: RetrieveRequest{UserID: "userID"},
			want: &oauth2.Token{
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: false,
		},
		{
			name: "RetrieveTokenNonExistingSecret",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "", &types.ResourceNotFoundException{}
				},
			},
			request: RetrieveRequest{UserID: "userID"},
			want:    nil,
			wantErr: true,
		},
		{
			name: "RetrieveTokenGetSecretError",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "secretID", nil
				},
				GetSecretFunc: func(request *secret.GetRequest) (string, error) {
					return "", &types.InvalidRequestException{}
				},
			},
			request: RetrieveRequest{UserID: "userID"},
			want:    nil,
			wantErr: true,
		},
		{
			name: "RetrieveTokenUnmarshalError",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "secretID", nil
				},
				GetSecretFunc: func(request *secret.GetRequest) (string, error) {
					return "invalid JSON", nil
				},
			},
			request: RetrieveRequest{UserID: "userID"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewOAuthManager(tt.stub)

			res, err := manager.RetrieveToken(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if res != nil && res.AccessToken != tt.want.AccessToken {
				t.Errorf("Retrieve() = %v, want %v", res.AccessToken, tt.want.AccessToken)
			}
		})
	}
}

func TestOAuthManager_Save(t *testing.T) {
	tests := []struct {
		name    string
		stub    *SecretManagerStub
		request SaveRequest
		wantErr bool
	}{
		{
			name: "SaveTokenExistingSecret",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "secretID", nil
				},
				PutSecretFunc: func(request *secret.PutRequest) error {
					return nil
				},
			},
			request: SaveRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: false,
		},
		{
			name: "SaveTokenCreateNewSecret",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "", &types.ResourceNotFoundException{}
				},
				CreateSecretFunc: func(request *secret.PutRequest) error {
					return nil
				},
			},
			request: SaveRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: false,
		},
		{
			name: "SaveTokenResolveSecretIDError",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "", &types.InvalidRequestException{}
				},
			},
			request: SaveRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: true,
		},
		{
			name: "SaveTokenCreateNewSecretError",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "", &types.ResourceNotFoundException{}
				},
				CreateSecretFunc: func(request *secret.PutRequest) error {
					return &types.InvalidRequestException{}
				},
			},
			request: SaveRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: true,
		},
		{
			name: "SaveTokenPutSecretError",
			stub: &SecretManagerStub{
				ResolveSecretIDFunc: func(request *secret.ResolveIDRequest) (string, error) {
					return "secretID", nil
				},
				PutSecretFunc: func(request *secret.PutRequest) error {
					return &types.InvalidRequestException{}
				},
			},
			request: SaveRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewOAuthManager(tt.stub)

			err := manager.SaveToken(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
