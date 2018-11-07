package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shelmangroup/oidc-agent/util"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	credentialStoreEnvVar = "OIDC_CREDENTIAL_STORE"
)

type tokens struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	IdToken      string     `json:"id_token"`
	TokenExpiry  *time.Time `json:"token_expiry"`
}
type config struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
}

type oidcCredentials struct {
	OIDCCreds  *tokens `json:"oidcCreds,omitempty"`
	OIDCConfig *config `json:"oidcConfig,omitempty"`
}

type OIDCAuth struct {
	conf           *oauth2.Config
	initialToken   *oauth2.Token
	InitialIdToken string
}

func (a *OIDCAuth) TokenSource(ctx context.Context) oauth2.TokenSource {
	return a.conf.TokenSource(ctx, a.initialToken)
}

type OIDCCredStore interface {
	GetOIDCAuth(name string) (*OIDCAuth, error)
	SetOIDCAuth(name, clientID, clientSecret string, tok *oauth2.Token) error
	DeleteOIDCAuth(name string) error
}

type credStore struct {
	credentialPath string
}

func NewOIDCCredStore() (OIDCCredStore, error) {
	path, err := oidcCredentialPath()
	return &credStore{
		credentialPath: path,
	}, err
}

func (s *credStore) GetOIDCAuth(name string) (*OIDCAuth, error) {
	creds, err := s.loadOIDCCredentials(name)
	if err != nil {
		if os.IsNotExist(err) {
			// No file, no credentials.
			return nil, err
		}
		return nil, err
	}

	if creds.OIDCCreds == nil {
		return nil, errors.New("OIDC Credentials not present in store")
	}

	var expiry time.Time
	if creds.OIDCCreds.TokenExpiry != nil {
		expiry = *creds.OIDCCreds.TokenExpiry
	}

	return &OIDCAuth{
		conf: &oauth2.Config{
			ClientID:     creds.OIDCConfig.ClientID,
			ClientSecret: creds.OIDCConfig.ClientSecret,
			Scopes:       creds.OIDCConfig.Scopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  "oob",
		},
		initialToken: &oauth2.Token{
			AccessToken:  creds.OIDCCreds.AccessToken,
			RefreshToken: creds.OIDCCreds.RefreshToken,
			Expiry:       expiry,
		},
		InitialIdToken: creds.OIDCCreds.IdToken,
	}, nil
}

// SetOIDCAuth sets the stored OIDC credentials.
func (s *credStore) SetOIDCAuth(name, clientID, clientSecret string, tok *oauth2.Token) error {
	creds, err := s.loadOIDCCredentials(name)
	if err != nil {
		// It's OK if we couldn't read any credentials,
		// making a new file.
		creds = &oidcCredentials{}
	}

	creds.OIDCCreds = &tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IdToken:      tok.Extra("id_token").(string),
		TokenExpiry:  &tok.Expiry,
	}

	creds.OIDCConfig = &config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/cloud-platform"},
	}

	return s.setOIDCCredentials(name, creds)
}

// DeleteOIDCAuth deletes the stored OIDC credentials.
func (s *credStore) DeleteOIDCAuth(name string) error {
	creds, err := s.loadOIDCCredentials(name)
	if err != nil {
		if os.IsNotExist(err) {
			// No file, no credentials.
			return nil
		}
		return err
	}

	// Optimization: only perform a 'set' if necessary
	if creds.OIDCCreds != nil {
		creds.OIDCCreds = nil
		return s.setOIDCCredentials(name, creds)
	}
	return nil
}

func oidcCredentialPath() (string, error) {
	if path := os.Getenv(credentialStoreEnvVar); strings.TrimSpace(path) != "" {
		return path, nil
	}

	configPath, err := util.CredentialsConfigPath()
	if err != nil {
		return "", err
	}
	return configPath, nil
}

func (s *credStore) createCredentialFile(name string) (*os.File, error) {
	// create the config dir, if it doesnt exist
	if err := os.MkdirAll(filepath.Dir(s.credentialPath), 0700); err != nil {
		return nil, err
	}
	// create the credential file, or truncate (clear) it if it exists
	path := filepath.Join(s.credentialPath, name)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (s *credStore) loadOIDCCredentials(name string) (*oidcCredentials, error) {
	path := filepath.Join(s.credentialPath, name)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var creds oidcCredentials
	if err := json.NewDecoder(f).Decode(&creds); err != nil {
		return nil, err
	}

	return &creds, nil
}

func (s *credStore) setOIDCCredentials(name string, creds *oidcCredentials) error {
	f, err := s.createCredentialFile(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(creds)
}
