package client

import (
	"encoding/json"
	"fmt"

	"github.com/shelmangroup/oidc-agent/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	command    = kingpin.Command("get", "Get Credential")
	name       = command.Flag("name", "Name of secret").Short('n').Required().String()
	output     = command.Flag("output", "What to output.").Short('o').Default("all").Enum("all", "id_token", "access_token", "token_expire")
	authHeader = command.Flag("auth-header", "add HTTP Authorization header").Bool()
)

func FullCommand() string {
	return command.FullCommand()
}

func RunGet() error {

	s, err := store.NewOIDCCredStore()
	if err != nil {
		return err
	}

	tokens, err := s.GetOIDCTokens(*name)
	if err != nil {
		return err
	}
	switch *output {
	case "all":
		output, err := json.MarshalIndent(tokens, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s", output)
	case "id_token":
		if *authHeader {
			fmt.Printf("Authorization: Bearer ")
		}
		fmt.Printf("%s", tokens.IDToken)
	case "access_token":
		if *authHeader {
			fmt.Printf("Authorization: Bearer ")
		}
		fmt.Printf("%s", tokens.AccessToken)
	case "token_expire":
		fmt.Printf("%s", tokens.TokenExpiry)
	}
	return nil
}
