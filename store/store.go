package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	_ "github.com/mattn/go-sqlite3"
	"github.com/shelmangroup/oidc-agent/util"
	"golang.org/x/oauth2"
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

type endpoint struct {
	TokenURL string `json:"token_url"`
	AuthURL  string `json:"auth_url"`
}

type config struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Scopes       []string  `json:"scopes"`
	Endpoint     *endpoint `json:"endpoint"`
}

type oidcCredentials struct {
	OIDCCreds  *tokens `json:"oidcCreds,omitempty"`
	OIDCConfig *config `json:"oidcConfig,omitempty"`
}

type OIDCTokens struct {
	AccessToken string    `json:"access_token,omitempty"`
	IDToken     string    `json:"id_token,omitempty"`
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
}

type OIDCCredStore interface {
	GetOIDCTokens(name string) (*OIDCTokens, error)
	SetOIDCAuth(name, clientID, clientSecret string, providerEndpoint oauth2.Endpoint, tok *oauth2.Token) error
	DeleteOIDCAuth(name string) error
}

type credStore struct {
	rootPath string
}

func NewOIDCCredStore() (OIDCCredStore, error) {
	path, err := oidcCredentialRootPath()
	return &credStore{
		rootPath: path,
	}, err
}

func (s *credStore) GetOIDCTokens(name string) (*OIDCTokens, error) {

	tokens, err := s.loadOIDCTokens(name)

	if err != nil {
		log.Printf("Unable to read tokens file for %s: %v\n", name, err)
	}

	if tokens != nil {
		if time.Now().Before(tokens.TokenExpiry) {
			return tokens, nil
		}
	}

	// tokens not loaded or expired
	tokens, err = s.refreshTokens(name)

	if err != nil {
		return nil, err
	}

	return tokens, nil

}

func (s *credStore) refreshTokens(name string) (*OIDCTokens, error) {
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

	conf := &oauth2.Config{
		ClientID:     creds.OIDCConfig.ClientID,
		ClientSecret: creds.OIDCConfig.ClientSecret,
		Scopes:       creds.OIDCConfig.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  creds.OIDCConfig.Endpoint.AuthURL,
			TokenURL: creds.OIDCConfig.Endpoint.TokenURL,
		},
		RedirectURL: "oob",
	}

	initialToken := &oauth2.Token{
		AccessToken:  creds.OIDCCreds.AccessToken,
		RefreshToken: creds.OIDCCreds.RefreshToken,
		Expiry:       expiry,
	}

	ts := conf.TokenSource(context.Background(), initialToken)

	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}

	tokens := &OIDCTokens{
		AccessToken: tok.AccessToken,
		IDToken:     tok.Extra("id_token").(string),
		TokenExpiry: tok.Expiry,
	}

	err = s.setOIDCTokens(name, tokens)

	if err != nil {
		return nil, err
	}

	return tokens, nil
}

// SetOIDCAuth sets the stored OIDC credentials.
func (s *credStore) SetOIDCAuth(name, clientID, clientSecret string, providerEndpoint oauth2.Endpoint, tok *oauth2.Token) error {
	creds, err := s.loadOIDCCredentials(name)
	if err != nil {
		// It's OK if we couldn't read any credentials,
		// making a new file.
		creds = &oidcCredentials{}
	}

	initialIDToken := tok.Extra("id_token").(string)

	creds.OIDCCreds = &tokens{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IdToken:      initialIDToken,
		TokenExpiry:  &tok.Expiry,
	}

	creds.OIDCConfig = &config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: &endpoint{
			AuthURL:  providerEndpoint.AuthURL,
			TokenURL: providerEndpoint.TokenURL,
		},
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	err = s.setOIDCCredentials(name, creds)
	if err != nil {
		return err
	}
	err = s.setOIDCTokens(name, &OIDCTokens{
		AccessToken: tok.AccessToken,
		IDToken:     initialIDToken,
		TokenExpiry: tok.Expiry,
	})
	if err != nil {
		return err
	}

	return nil
}

// DeleteOIDCAuth deletes the stored OIDC credentials.
func (s *credStore) DeleteOIDCAuth(name string) error {

	filesToDelete := []string{
		s.getTokenPath(name),
		s.getCredentialsPath(name),
	}

	for _, path := range filesToDelete {
		if _, err := os.Stat(path); err == nil {
			return os.Remove(path)
		}
		return nil
	}

	return nil
}

func oidcCredentialRootPath() (string, error) {
	if path := os.Getenv(credentialStoreEnvVar); strings.TrimSpace(path) != "" {
		return path, nil
	}

	configPath, err := util.CredentialsConfigPath()
	if err != nil {
		return "", err
	}
	return configPath, nil
}

func (s *credStore) getCredentialsPath(name string) string {
	return filepath.Join(s.rootPath, name)
}

func (s *credStore) createCredentialFile(name string) (*os.File, error) {
	// create the config dir, if it doesnt exist
	if err := os.MkdirAll(s.rootPath, 0700); err != nil {
		return nil, err
	}
	// create the credential file, or truncate (clear) it if it exists
	path := s.getCredentialsPath(name)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (s *credStore) loadOIDCCredentials(name string) (*oidcCredentials, error) {
	path := s.getCredentialsPath(name)
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

func (s *credStore) getTokenPath(name string) string {
	return filepath.Join(s.rootPath, fmt.Sprintf("%s_tokens", name))
}

func (s *credStore) createTokensFile(name string) (*os.File, error) {
	// create the config dir, if it doesnt exist
	if err := os.MkdirAll(s.rootPath, 0700); err != nil {
		return nil, err
	}
	// create the credential file, or truncate (clear) it if it exists
	path := s.getTokenPath(name)
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (s *credStore) loadOIDCTokens(name string) (*OIDCTokens, error) {
	path := s.getTokenPath(name)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tokens := &OIDCTokens{}
	if err := json.NewDecoder(f).Decode(tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

func (s *credStore) setOIDCTokens(name string, tokens *OIDCTokens) error {
	f, err := s.createTokensFile(name)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(tokens)
}
