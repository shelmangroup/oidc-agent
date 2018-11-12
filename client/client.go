package client

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes"
	pb "github.com/shelmangroup/oidc-agent/proto"
	"google.golang.org/grpc"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	command    = kingpin.Command("get", "Get")
	name       = command.Flag("name", "Name of secret").Short('n').Required().String()
	address    = command.Flag("server", "Server address.").Short('l').Default("127.0.0.1:1337").String()
	output     = command.Flag("output", "What to output.").Short('o').Default("all").String()
	authHeader = command.Flag("auth-header", "add HTTP Authorization header").Bool()
)

func FullCommand() string {
	return command.FullCommand()
}

func RunGet() error {
	// Set up a connection to the server.
	conn, err := grpc.Dial(*address, grpc.WithInsecure())
	if err != nil {
		return err
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
		{
			fmt.Printf("IdToken: %s\n", r.IdToken)
			fmt.Printf("AccessToken: %s\n", r.AccessToken)
			fmt.Printf("Expire: %s\n", expiry)
		}
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
