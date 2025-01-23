package token

import (
	"app/api"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"golang.org/x/oauth2"
	"testing"
)

type SecretFuncStub struct {
	ResolveSecretIDFunc func(request *api.ResolveSecretRequest) (string, error)
	GetSecretFunc       func(request *api.GetSecretRequest) (string, error)
	PutSecretFunc       func(request *api.PutSecretRequest) error
	CreateSecretFunc    func(request *api.CreateSecretRequest) error
}

func (s *SecretFuncStub) ResolveSecretID(request *api.ResolveSecretRequest) (string, error) {
	return s.ResolveSecretIDFunc(request)
}

func (s *SecretFuncStub) GetSecret(request *api.GetSecretRequest) (string, error) {
	return s.GetSecretFunc(request)
}

func (s *SecretFuncStub) PutSecret(request *api.PutSecretRequest) error {
	return s.PutSecretFunc(request)
}

func (s *SecretFuncStub) CreateSecret(request *api.CreateSecretRequest) error {
	return s.CreateSecretFunc(request)
}

func TestOAuthManager_Retrieve(t *testing.T) {
	tests := []struct {
		name    string
		stub    *SecretFuncStub
		request api.RetrieveTokenRequest
		want    *oauth2.Token
		wantErr bool
	}{
		{
			name: "RetrieveTokenSuccess",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "secretID", nil
				},
				GetSecretFunc: func(request *api.GetSecretRequest) (string, error) {
					return `{"access_token":  "access_token", 
							 "token_type":    "Bearer",
							 "refresh_token": "refresh_token"}`, nil
				},
			},
			request: api.RetrieveTokenRequest{UserID: "userID"},
			want: &oauth2.Token{
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: false,
		},
		{
			name: "RetrieveTokenNonExistingSecret",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "", &types.ResourceNotFoundException{}
				},
			},
			request: api.RetrieveTokenRequest{UserID: "userID"},
			want:    nil,
			wantErr: true,
		},
		{
			name: "RetrieveTokenGetSecretError",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "secretID", nil
				},
				GetSecretFunc: func(request *api.GetSecretRequest) (string, error) {
					return "", &types.InvalidRequestException{}
				},
			},
			request: api.RetrieveTokenRequest{UserID: "userID"},
			want:    nil,
			wantErr: true,
		},
		{
			name: "RetrieveTokenUnmarshalError",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "secretID", nil
				},
				GetSecretFunc: func(request *api.GetSecretRequest) (string, error) {
					return "invalid JSON", nil
				},
			},
			request: api.RetrieveTokenRequest{UserID: "userID"},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retr := ApiRetriever{tt.stub, tt.stub}

			res, err := retr.RetrieveToken(&tt.request)
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
		stub    *SecretFuncStub
		request api.SaveTokenRequest
		wantErr bool
	}{
		{
			name: "SaveTokenExistingSecret",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "secretID", nil
				},
				PutSecretFunc: func(request *api.PutSecretRequest) error {
					return nil
				},
			},
			request: api.SaveTokenRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: false,
		},
		{
			name: "SaveTokenCreateNewSecret",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "", &types.ResourceNotFoundException{}
				},
				CreateSecretFunc: func(request *api.CreateSecretRequest) error {
					return nil
				},
			},
			request: api.SaveTokenRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: false,
		},
		{
			name: "SaveTokenResolveSecretIDError",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "", &types.InvalidRequestException{}
				},
			},
			request: api.SaveTokenRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: true,
		},
		{
			name: "SaveTokenCreateNewSecretError",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "", &types.ResourceNotFoundException{}
				},
				CreateSecretFunc: func(request *api.CreateSecretRequest) error {
					return &types.InvalidRequestException{}
				},
			},
			request: api.SaveTokenRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: true,
		},
		{
			name: "SaveTokenPutSecretError",
			stub: &SecretFuncStub{
				ResolveSecretIDFunc: func(request *api.ResolveSecretRequest) (string, error) {
					return "secretID", nil
				},
				PutSecretFunc: func(request *api.PutSecretRequest) error {
					return &types.InvalidRequestException{}
				},
			},
			request: api.SaveTokenRequest{
				UserID:       "userID",
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svr := ApiSaver{tt.stub, tt.stub, tt.stub}

			err := svr.SaveToken(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("Save() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
