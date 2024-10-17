package oauth

import (
	"app/internal/services/secretmanager"
	"context"
	"fmt"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/sheets/v4"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const credentialsFilePath = "C:\\Users\\jakub\\GolandProjects\\StackedTracker\\config\\credentials.json"

type GoogleService struct {
	config               *oauth2.Config
	secretManagerService secretmanager.ServiceInterface
}

func NewGoogleService(secretManagerService secretmanager.ServiceInterface) (ServiceInterface, error) {
	fileByte, err := os.ReadFile(credentialsFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read google api credentials: %v", err)
	}

	config, err := google.ConfigFromJSON(fileByte, "openid", drive.DriveScope, sheets.SpreadsheetsScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse google api credentials to config: %v", err)
	}

	return &GoogleService{config, secretManagerService}, nil
}

func (service GoogleService) CreateClientFromToken() (*http.Client, error) {
	config := service.config

	// check if token in secret manager, if so return token
	token, err := service.secretManagerService.LoadSecret("stackedtracker-oauth")
	if err != nil {
		return nil, fmt.Errorf("unable to get token from secret manager: %v", err)
	} else if token.Valid() {
		return config.Client(context.Background(), token), nil
	}

	// get token generated from authenticator code
	token, err = service.getTokenFromWeb(config)
	if err != nil {
		return nil, fmt.Errorf("unable to get token: %v", err)
	}

	// store token in secret manager
	err = service.secretManagerService.StoreSecret("stackedtracker-oauth", token)
	if err != nil {
		return nil, fmt.Errorf("unable to store token in secrets manager: %v", err)
	}

	// return client with generated token
	return config.Client(context.Background(), token), nil
}

func (service GoogleService) getTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	for {
		authCode, err := service.askForAuthCode(config)
		if err != nil {
			fmt.Printf("Error retrieving auth code: %v. Please try again.\n", err)
			continue // retry if user input was invalid
		}

		token, err := config.Exchange(context.TODO(), authCode)
		if err != nil {
			return nil, fmt.Errorf("unable to convert token from authorization code: %v", err)
		}

		return token, nil
	}
}

func (service GoogleService) askForAuthCode(config *oauth2.Config) (string, error) {
	// get authentication url and tell user to enter auth code
	var authURL = config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	// define authorization code
	var authCode string

	// scan users entry, show error if invalid
	_, err := fmt.Scan(&authCode)
	if err != nil {
		return "", err
	}

	return authCode, nil
}
