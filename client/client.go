package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/shelmangroup/oidc-agent/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	command    = kingpin.Command("get", "Get Credential")
	name       = command.Flag("name", "Name of secret").Short('n').Required().String()
	address    = command.Flag("server", "Server address.").Short('l').Default("127.0.0.1:1337").String()
	output     = command.Flag("output", "What to output. <all|id_token|access_token|token_expire>").Short('o').Default("all").String()
	authHeader = command.Flag("auth-header", "add HTTP Authorization header").Bool()
)

type token struct {
	AccessToken string    `json:"access_token"`
	IdToken     string    `json:"id_token"`
	TokenExpiry time.Time `json:"token_expiry"`
}

func FullCommand() string {
	return command.FullCommand()
}

func RunGet() error {
	// Set up a connection to the server.
	sock := filepath.Join(os.Getenv("HOME"), ".oidc-agent.sock")
	conn, err := grpc.Dial("unix://"+sock, grpc.WithInsecure())
	if err != nil {
		log.Warnf("falling back to tcp: %s", *address)
		conn, err = grpc.Dial(*address, grpc.WithInsecure())
		if err != nil {
			return err
		}
	}
	defer conn.Close()
	c := pb.NewOIDCAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.Get(ctx, &pb.GetRequest{Name: *name})
	if err != nil {
		return err
	}
	expiry, err := ptypes.Timestamp(r.TokenExpiry)
	if err != nil {
		return err
	}

	switch *output {
	case "all":
		creds := &token{
			AccessToken: r.AccessToken,
			IdToken:     r.IdToken,
			TokenExpiry: expiry,
		}
		output, err := json.MarshalIndent(creds, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s", output)
	case "id_token":
		if *authHeader {
			fmt.Printf("Authorization: Bearer ")
		}
		fmt.Printf("%s", r.IdToken)
	case "access_token":
		if *authHeader {
			fmt.Printf("Authorization: Bearer ")
		}
		fmt.Printf("%s", r.AccessToken)
	case "token_expire":
		fmt.Printf("%s", expiry)
	}
	return nil
}
