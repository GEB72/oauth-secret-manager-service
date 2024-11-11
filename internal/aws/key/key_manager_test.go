package key

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"testing"
)

type AWSKeyClientStub struct {
	GetPublicKeyFunc func(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (
		*kms.GetPublicKeyOutput, error)
}

func (s *AWSKeyClientStub) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput,
	opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return s.GetPublicKeyFunc(ctx, input, opts...)
}

func TestAWSManager_GetPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		stub    func() *AWSKeyClientStub
		want    []byte
		wantErr bool
	}{
		{
			name: "GetExistingPublicKey",
			stub: func() *AWSKeyClientStub {
				return &AWSKeyClientStub{
					GetPublicKeyFunc: func(ctx context.Context, input *kms.GetPublicKeyInput,
						opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
						return &kms.GetPublicKeyOutput{
							PublicKey: []byte("PublicKey"),
						}, nil
					},
				}
			},
			want:    []byte("PublicKey"),
			wantErr: false,
		},
		{
			name: "GetNonExistingPublicKey",
			stub: func() *AWSKeyClientStub {
				return &AWSKeyClientStub{
					GetPublicKeyFunc: func(ctx context.Context, input *kms.GetPublicKeyInput,
						opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
						return nil, &types.NotFoundException{}
					},
				}
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := AWSManager{client: tt.stub()}

			res, err := manager.GetPublicKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if string(res) != string(tt.want) {
				t.Errorf("GetPublicKey() = %v, want %v", res, tt.want)
			}
		})
	}
}
