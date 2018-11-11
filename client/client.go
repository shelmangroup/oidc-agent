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
	command = kingpin.Command("get", "Get")
	name    = command.Flag("name", "Name of secret").Short('n').Required().String()
	address = command.Flag("server", "Server address.").Short('l').Default("127.0.0.1:1337").String()
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
	fmt.Printf("IdToken: %s\n", r.IdToken)
	fmt.Printf("Expire: %s\n", expiry)
	return nil
}
