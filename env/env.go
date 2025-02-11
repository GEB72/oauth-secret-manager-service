package env

import (
	"fmt"
	"github.com/joho/godotenv"
	"log/slog"
	"os"
)

type AwsVars struct {
	SmsRootDomain string
	KmsKeyID      string
}

func GetAwsVars() (AwsVars, error) {
	err := godotenv.Load()
	if err != nil {
		slog.Info("No env file found, using os environment variables")
	}

	rootDomain := os.Getenv("SMS_ROOT_DOMAIN")
	if rootDomain == "" {
		return AwsVars{}, fmt.Errorf("SMS_ROOT_DOMAIN environment variable not set")
	}

	keyID := os.Getenv("KMS_KEY_ID")
	if keyID == "" {
		return AwsVars{}, fmt.Errorf("KMS_KEY_ID environment variable not set")
	}

	return AwsVars{SmsRootDomain: rootDomain, KmsKeyID: keyID}, nil
}
