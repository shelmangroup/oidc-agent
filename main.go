package main

import (
	"github.com/shelmangroup/oidc-agent/login"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.CommandLine.DefaultEnvars()
	kingpin.Parse()

	switch kingpin.Parse() {
	case login.FullCommand():
		login.RunLogin()
	}
}
