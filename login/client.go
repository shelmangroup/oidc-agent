package login

import (
	"github.com/shelmangroup/oidc-agent/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	command          = kingpin.Command("login", "Start a new login flow")
	skipBrowser      = command.Flag("skip-browser", "Try not to open up the browser").Bool()
	clientID         = command.Flag("client-id", "OIDC Client ID").Required().String()
	clientSecret     = command.Flag("client-secret", "OIDC Client Secret").Required().String()
	name             = command.Flag("name", "Name the secret").Short('n').Required().String()
	providerEndpoint = command.Flag("provider-endpoint", "URL to provider").Short('p').Default("https://accounts.google.com").String()
	callbackPort     = command.Flag("callback-port", "port to listen on for callbacks").Default("0").Int()
	extraScope       = command.Flag("extra-scope", "request extra scope").Strings()
)

func FullCommand() string {
	return command.FullCommand()
}

func RunLogin() error {
	s, err := store.NewOIDCCredStore()
	if err != nil {
		return err
	}

	login := &LoginAgent{
		SkipBrowser:  *skipBrowser,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
	}
	ts, err := login.PerformLogin(*providerEndpoint, *callbackPort, *extraScope)
	if err != nil {
		return err
	}
	token, err := ts.Token()
	if err != nil {
		return err
	}

	s.SetOIDCAuth(*name, *providerEndpoint, *clientID, *clientSecret, token)
	return nil
}
