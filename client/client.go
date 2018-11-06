package client

import (
	"github.com/shelmangroup/oidc-agent/store"
)

func NewLoginClient(clientId, clientSecret string) error {
	login := &LoginAgent{
		AllowBrowser: true,
		ClientID:     "", //config.ClientID
		ClientSecret: "", //config.ClientSecret
	}

	ts, err := login.PerformLogin()
	if err != nil {
		return err
	}
	token, err := ts.Token()
	if err != nil {
		return err
	}

	s := store.NewOIDCCredStore("/tmp")
	s.SetOIDCAuth(token)
	return nil
}
