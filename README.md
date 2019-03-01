# oidc-agent

A cross platform OIDC agent that will manange your OIDC tokens through a single gRPC API,
inspired by ssh-agent/gpg-agent. Agent will automaticly refresh token upon expiry. Perfect
tool for writing command line applications or debug your OIDC application from the command line
with tools like `curl`.

The agent can also be used as a credential helper for services like `kubernetes` or `git`.

## Usage

### Create a Oauth2 client ID.

Create a new client ID/Secret at your preferred provider (defaults to google cloud)
with the callback url set to `http://localhost`.

### Start a new login dance.

Starta a new OIDC login flow with a google cloud. (will open a browser for you to complete the login)

Example:
```bash
$ oidc-agent login \
  --client-id xyz.apps.googleusercontent.com \
  --client-secret hT-bK074kBbbYBpO7USsFTiO \
  -n my-app
```

Starta a new OIDC login flow with another provider.

Example:
```bash
$ oidc-agent login \
  -p https://mycompany.eu.auth0.com \
  --client-id login-app \
  --client-secret NotSoSecret \
  --callback-port 31337 \
  --extra-scope offline_access \
  -n my-app

```

This will cache the initial credentials in `~/.config/oidc-agent/my-app` or `%UserProfile%\AppData\Roaming\oidc-agent\my-app` on windows.

### Start the OIDC Agent Server.

```bash
$ oidc-agent server
```

### Fetch credentials from server.

will output `access_token`, `id_token`, and `token_expiry` in json format.
```bash
$ oidc-agent get -n my-app
```

Add authorization header
```bash
$ curl -H "$(oidc-agent get -n my-app --auth-header -o id_token)" https://my-app.example.com
```

### kubectl credential helper

```bash
$ kubectl config set-credentials \
  --auth-provider=gcp \
  --auth-provider-arg=cmd-path=/path/to/oidc-agent \
  --auth-provider-arg=cmd-args="get -n my-cluster-cred" \
  --auth-provider-arg=token-key='{.access_token}' \
  --auth-provider-arg=expiry-key='{.token_expiry}' \
  my-cluster-cred
```
