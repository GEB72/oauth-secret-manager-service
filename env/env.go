package env

import (
	"fmt"
	"os"
)

type AwsVars struct {
	SmsRootDomain string
	KmsKeyID      string
}

func GetAwsVars() (AwsVars, error) {
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
