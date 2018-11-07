package main

import (
	"log"

	"github.com/shelmangroup/oidc-agent/client"
	"github.com/shelmangroup/oidc-agent/login"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.CommandLine.DefaultEnvars()
	kingpin.Parse()

	var err error

	switch kingpin.Parse() {
	case login.FullCommand():
		err = login.RunLogin()
	case client.FullCommand():
		err = client.RunGet()
	}
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	return
}
