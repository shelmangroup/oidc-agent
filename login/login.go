package login

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/toqueteos/webbrowser"
	"golang.org/x/oauth2"
)

const redirectURIAuthCodeInTitleBar = "urn:ietf:wg:oauth:2.0:oob"

var promptConsent oauth2.AuthCodeOption = oauth2.SetAuthURLParam("prompt", "consent")

// LoginAgent implements the OAuth2 login dance, generating an Oauth2 access_token
// for the user. If AllowBrowser is set to true, the agent will attempt to
// obtain an authorization_code automatically by executing OpenBrowser and
// reading the redirect performed after a successful login. Otherwise, it will
// attempt to use In and Out to direct the user to the login portal and receive
// the authorization_code in response.
type LoginAgent struct {
	// Whether to execute OpenBrowser when authenticating the user.
	SkipBrowser bool

	// Read input from here; if nil, uses os.Stdin.
	In io.Reader

	// Write output to here; if nil, uses os.Stdout.
	Out io.Writer

	// Open the browser for the given url.  If nil, uses webbrowser.Open.
	OpenBrowser func(url string) error

	// OIDC Client id/secret
	ClientID     string
	ClientSecret string
	Audience     string

	Endpoint   oauth2.Endpoint
	ExtraScope []string
}

// populate missing fields as described in the struct definition comments
func (a *LoginAgent) init() {
	if a.In == nil {
		a.In = os.Stdin
	}
	if a.Out == nil {
		a.Out = os.Stdout
	}
	if a.OpenBrowser == nil {
		a.OpenBrowser = webbrowser.Open
	}
}

// PerformLogin performs the auth dance necessary to obtain an
// authorization_code from the user and exchange it for an Oauth2 access_token.
func (a *LoginAgent) PerformLogin(callbackPort int) (oauth2.TokenSource, error) {
	a.init()

	scope := []string{"openid", "profile", "email"}
	if len(a.ExtraScope) > 0 {
		scope = append(scope, a.ExtraScope...)
	}

	conf := &oauth2.Config{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Endpoint:     a.Endpoint,
		Scopes:       scope,
	}

	if !a.SkipBrowser {
		// Attempt to receive the authorization code via redirect URL
		if ln, port, err := getListener(callbackPort); err == nil {
			defer ln.Close()
			// open a web browser and listen on the redirect URL port
			conf.RedirectURL = fmt.Sprintf("http://localhost:%d", port)
			aud := oauth2.SetAuthURLParam("audience", a.Audience)
			url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, promptConsent, aud)
			if err := a.OpenBrowser(url); err == nil {
				if code, err := handleCodeResponse(ln); err == nil {
					token, err := conf.Exchange(oauth2.NoContext, code)
					if err != nil {
						return nil, err
					}
					return conf.TokenSource(oauth2.NoContext, token), nil
				}
			}
		}
	}

	// If we can't or shouldn't automatically retrieve the code via browser,
	// default to a command line prompt.
	code, err := a.codeViaPrompt(conf)
	if err != nil {
		return nil, err
	}

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}
	return conf.TokenSource(oauth2.NoContext, token), nil
}

func (a *LoginAgent) codeViaPrompt(conf *oauth2.Config) (string, error) {
	// Direct the user to our login portal
	conf.RedirectURL = redirectURIAuthCodeInTitleBar
	aud := oauth2.SetAuthURLParam("audience", a.Audience)
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, promptConsent, aud)
	fmt.Fprintln(a.Out, "Please visit the following URL and complete the authorization dialog:")
	fmt.Fprintf(a.Out, "%v\n", url)

	// Receive the authorization_code in response
	fmt.Fprintln(a.Out, "Authorization code:")
	var code string
	if _, err := fmt.Fscan(a.In, &code); err != nil {
		return "", err
	}

	return code, nil
}

func getListener(port int) (net.Listener, int, error) {
	laddr := net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port} // port: 0 == find free port
	ln, err := net.ListenTCP("tcp4", &laddr)
	if err != nil {
		return nil, 0, err
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, nil
}

func handleCodeResponse(ln net.Listener) (string, error) {
	conn, err := ln.Accept()
	if err != nil {
		return "", err
	}

	srvConn := httputil.NewServerConn(conn, nil)
	defer srvConn.Close()

	req, err := srvConn.Read()
	if err != nil {
		return "", err
	}

	code := req.URL.Query().Get("code")

	resp := &http.Response{
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Close:         true,
		ContentLength: -1, // designates unknown length
	}
	defer srvConn.Write(req, resp)

	// If the code couldn't be obtained, inform the user via the browser and
	// return an error.
	// TODO i18n?
	if code == "" {
		err := fmt.Errorf("Code not present in response: %s", req.URL.String())
		resp.Body = getResponseBody("ERROR: Authentication code not present in response, please retry with --no-browser.")
		return "", err
	}

	resp.Body = getResponseBody("Success! You may now close your browser.")
	return code, nil
}

// turn a string into an io.ReadCloser as required by an http.Response
func getResponseBody(body string) io.ReadCloser {
	reader := strings.NewReader(body)
	return ioutil.NopCloser(reader)
}
