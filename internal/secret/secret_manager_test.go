package secret

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"testing"
)

type AWSClientStub struct {
	GetSecretValueFunc func(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (
		*sm.GetSecretValueOutput, error)
	PutSecretValueFunc func(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (
		*sm.PutSecretValueOutput, error)
	CreateSecretFunc func(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (
		*sm.CreateSecretOutput, error)
	DescribeSecretFunc func(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (
		*sm.DescribeSecretOutput, error)
}

func (s *AWSClientStub) GetSecretValue(ctx context.Context, input *sm.GetSecretValueInput, opts ...func(*sm.Options)) (
	*sm.GetSecretValueOutput, error) {
	return s.GetSecretValueFunc(ctx, input, opts...)
}

func (s *AWSClientStub) PutSecretValue(ctx context.Context, input *sm.PutSecretValueInput, opts ...func(*sm.Options)) (
	*sm.PutSecretValueOutput, error) {
	return s.PutSecretValueFunc(ctx, input, opts...)
}

func (s *AWSClientStub) CreateSecret(ctx context.Context, input *sm.CreateSecretInput, opts ...func(*sm.Options)) (
	*sm.CreateSecretOutput, error) {
	return s.CreateSecretFunc(ctx, input, opts...)
}

func (s *AWSClientStub) DescribeSecret(ctx context.Context, input *sm.DescribeSecretInput, opts ...func(*sm.Options)) (
	*sm.DescribeSecretOutput, error) {
	return s.DescribeSecretFunc(ctx, input, opts...)
}

func TestAWSManager_GetSecret(t *testing.T) {
	tests := []struct {
		name    string
		stub    func() *AWSClientStub
		request GetRequest
		want    string
		wantErr bool
	}{
		{
			name: "GetExistingSecret",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					GetSecretValueFunc: func(
						ctx context.Context,
						input *sm.GetSecretValueInput,
						opts ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
						return &sm.GetSecretValueOutput{SecretString: aws.String("secretValue")}, nil
					},
				}
			},
			request: GetRequest{SecretID: "secretID"},
			want:    "secretValue",
			wantErr: false,
		},
		{
			name: "GetNonExistingSecret",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					GetSecretValueFunc: func(
						ctx context.Context,
						input *sm.GetSecretValueInput,
						opts ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
						return nil, &types.ResourceNotFoundException{}
					},
				}
			},
			request: GetRequest{SecretID: "secretID"},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := AWSManager{client: tt.stub()}

			res, err := manager.GetSecret(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
			if res != tt.want {
				t.Errorf("GetSecret() = %v, want %v", res, tt.want)
			}
		})
	}
}

func TestAWSManager_PutSecret(t *testing.T) {
	tests := []struct {
		name    string
		stub    func() *AWSClientStub
		request PutRequest
		wantErr bool
	}{
		{
			name: "PutSecretSuccess",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					PutSecretValueFunc: func(
						ctx context.Context,
						input *sm.PutSecretValueInput,
						opts ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
						return &sm.PutSecretValueOutput{}, nil
					},
				}
			},
			request: PutRequest{"secretID", "token"},
			wantErr: false,
		},
		{
			name: "PutSecretFailure",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					PutSecretValueFunc: func(
						ctx context.Context,
						input *sm.PutSecretValueInput,
						opts ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
						return nil, &types.ResourceNotFoundException{}
					},
				}
			},
			request: PutRequest{SecretID: "secretID", Token: "token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := AWSManager{client: tt.stub()}

			err := manager.PutSecret(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("PutSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWSManager_CreateSecret(t *testing.T) {
	tests := []struct {
		name    string
		stub    func() *AWSClientStub
		request PutRequest
		wantErr bool
	}{
		{
			name: "CreateSecretSuccess",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					CreateSecretFunc: func(
						ctx context.Context,
						input *sm.CreateSecretInput,
						opts ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
						return &sm.CreateSecretOutput{}, nil
					},
				}
			},
			request: PutRequest{SecretID: "secretID", Token: "token"},
			wantErr: false,
		},
		{
			name: "CreateSecretFailure",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					CreateSecretFunc: func(
						ctx context.Context,
						input *sm.CreateSecretInput,
						opts ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
						return nil, &types.LimitExceededException{}
					},
				}
			},
			request: PutRequest{SecretID: "secretID", Token: "token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := AWSManager{client: tt.stub()}

			err := manager.CreateSecret(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWSManager_ResolveID(t *testing.T) {
	tests := []struct {
		name    string
		stub    func() *AWSClientStub
		request ResolveIDRequest
		want    string
		wantErr bool
	}{
		{
			name: "ResolveExistingSecretID",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					DescribeSecretFunc: func(
						ctx context.Context,
						input *sm.DescribeSecretInput,
						opts ...func(*sm.Options)) (*sm.DescribeSecretOutput, error) {
						return &sm.DescribeSecretOutput{}, nil
					},
				}
			},
			request: ResolveIDRequest{UserID: "userID"},
			want:    "stackedtracker-oauth/userID",
			wantErr: false,
		},
		{
			name: "ResolveNonExistingSecretID",
			stub: func() *AWSClientStub {
				return &AWSClientStub{
					DescribeSecretFunc: func(
						ctx context.Context,
						input *sm.DescribeSecretInput,
						opts ...func(*sm.Options)) (*sm.DescribeSecretOutput, error) {
						return nil, &types.ResourceNotFoundException{}
					},
				}
			},
			request: ResolveIDRequest{UserID: "userID"},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := AWSManager{client: tt.stub()}

			res, err := manager.ResolveSecretID(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveSecretID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if res != tt.want {
				t.Errorf("ResolveSecretID() = %v, want %v", res, tt.want)
			}
		})
	}
}

func TestIsErrorResourceNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "ErrorIsResourceNotFound",
			err:  &types.ResourceNotFoundException{},
			want: true,
		},
		{
			name: "ErrorIsNotResourceNotFound",
			err:  &types.InvalidRequestException{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := IsErrorResourceNotFound(tt.err)
			if res != tt.want {
				t.Errorf("IsErrorResourceNotFound() = %v, want %v", res, tt.want)
			}
		})
	}
}
