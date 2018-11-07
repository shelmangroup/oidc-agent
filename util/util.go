package util

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

func CredentialsConfigPath() (string, error) {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "oidc-agent"), nil
	}
	homeDir := unixHomeDir()
	if homeDir == "" {
		return "", fmt.Errorf("unable to get current user home directory: os/user lookup failed; $HOME is empty")
	}
	return filepath.Join(homeDir, ".config", "oidc-agent"), nil
}

func unixHomeDir() string {
	usr, err := user.Current()
	if err == nil {
		return usr.HomeDir
	}
	return os.Getenv("HOME")
}
