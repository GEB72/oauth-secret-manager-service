package secret

import (
	"app/api"
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
		stub    *AWSClientStub
		request api.GetSecretRequest
		want    string
		wantErr bool
	}{
		{
			name: "GetExistingSecret",
			stub: &AWSClientStub{
				GetSecretValueFunc: func(ctx context.Context, input *sm.GetSecretValueInput,
					opts ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
					return &sm.GetSecretValueOutput{SecretString: aws.String("SecretValue")}, nil
				},
			},
			request: api.GetSecretRequest{SecretID: "root-domain/domain/userID"},
			want:    "SecretValue",
			wantErr: false,
		},
		{
			name: "GetNonExistingSecret",
			stub: &AWSClientStub{
				GetSecretValueFunc: func(
					ctx context.Context,
					input *sm.GetSecretValueInput,
					opts ...func(*sm.Options)) (*sm.GetSecretValueOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				},
			},
			request: api.GetSecretRequest{SecretID: "root-domain/domain/userID"},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gtr := AWSGetter{Client: tt.stub}

			res, err := gtr.GetSecret(&tt.request)
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
		stub    *AWSClientStub
		request api.PutSecretRequest
		wantErr bool
	}{
		{
			name: "PutSecretSuccess",
			stub: &AWSClientStub{
				PutSecretValueFunc: func(
					ctx context.Context,
					input *sm.PutSecretValueInput,
					opts ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
					return &sm.PutSecretValueOutput{}, nil
				},
			},
			request: api.PutSecretRequest{SecretID: "root-domain/domain/userID", Token: "Token"},
			wantErr: false,
		},
		{
			name: "PutSecretFailure",
			stub: &AWSClientStub{
				PutSecretValueFunc: func(
					ctx context.Context,
					input *sm.PutSecretValueInput,
					opts ...func(*sm.Options)) (*sm.PutSecretValueOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				},
			},
			request: api.PutSecretRequest{SecretID: "root-domain/domain/userID", Token: "Token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ptr := AWSPutter{Client: tt.stub}

			err := ptr.PutSecret(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("PutSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWSManager_CreateSecret(t *testing.T) {
	tests := []struct {
		name    string
		stub    *AWSClientStub
		request api.CreateSecretRequest
		wantErr bool
	}{
		{
			name: "CreateSecretSuccess",
			stub: &AWSClientStub{
				CreateSecretFunc: func(
					ctx context.Context,
					input *sm.CreateSecretInput,
					opts ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
					return &sm.CreateSecretOutput{}, nil
				},
			},
			request: api.CreateSecretRequest{SecretID: "root-domain/domain/userID", Token: "token"},
			wantErr: false,
		},
		{
			name: "CreateSecretFailure",
			stub: &AWSClientStub{
				CreateSecretFunc: func(
					ctx context.Context,
					input *sm.CreateSecretInput,
					opts ...func(*sm.Options)) (*sm.CreateSecretOutput, error) {
					return nil, &types.LimitExceededException{}
				},
			},
			request: api.CreateSecretRequest{SecretID: "root-domain/domain/userID", Token: "token"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctr := AWSCreator{Client: tt.stub}

			err := ctr.CreateSecret(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAWSManager_ResolveID(t *testing.T) {
	tests := []struct {
		name    string
		stub    *AWSClientStub
		request api.ResolveSecretRequest
		want    string
		wantErr bool
	}{
		{
			name: "ResolveExistingSecretID",
			stub: &AWSClientStub{
				DescribeSecretFunc: func(
					ctx context.Context,
					input *sm.DescribeSecretInput,
					opts ...func(*sm.Options)) (*sm.DescribeSecretOutput, error) {
					return &sm.DescribeSecretOutput{}, nil
				},
			},
			request: api.ResolveSecretRequest{
				RootDomain: "root-domain",
				Domain:     "domain",
				UserID:     "userID",
			},
			want:    "root-domain/domain/userID",
			wantErr: false,
		},
		{
			name: "ResolveNonExistingSecretID",
			stub: &AWSClientStub{
				DescribeSecretFunc: func(
					ctx context.Context,
					input *sm.DescribeSecretInput,
					opts ...func(*sm.Options)) (*sm.DescribeSecretOutput, error) {
					return nil, &types.ResourceNotFoundException{}
				},
			},
			request: api.ResolveSecretRequest{
				RootDomain: "root-domain",
				Domain:     "domain",
				UserID:     "userID",
			},
			want:    "root-domain/domain/userID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rsr := AWSResolver{Client: tt.stub}

			res, err := rsr.ResolveSecretID(&tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveSecretID() error = %v, wantErr %v", err, tt.wantErr)
			}
			if res != tt.want {
				t.Errorf("ResolveSecretID() = %v, want = %v", res, tt.want)
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
