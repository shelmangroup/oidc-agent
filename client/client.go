package client

import (
	"context"
	"fmt"

	"github.com/shelmangroup/oidc-agent/store"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	command = kingpin.Command("get", "Get")
	name    = command.Flag("name", "Name of secret").Short('n').Required().String()
)

func FullCommand() string {
	return command.FullCommand()
}

func RunGet() error {
	s, err := store.NewOIDCCredStore()
	if err != nil {
		return err
	}

	cred, err := s.GetOIDCAuth(*name)
	if err != nil {
		return err
	}

	ts := cred.TokenSource(context.Background())
	tok, err := ts.Token()
	if err != nil {
		return err
	}
	if !tok.Valid() {
		return err
	}
	idToken := tok.Extra("id_token")
	if idToken == nil {
		idToken = cred.InitialIdToken
	}
	fmt.Printf("TokenID: %s\n", idToken.(string))
	return nil
}
