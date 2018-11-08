package server

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/shelmangroup/oidc-agent/proto"
	"github.com/shelmangroup/oidc-agent/store"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	command    = kingpin.Command("server", "Server")
	listenAddr = command.Flag("listen", "Listen address.").Short('l').Default(":1337").String()
)

type Server struct {
	tokenCache map[string]oauth2.TokenSource
}

func FullCommand() string {
	return command.FullCommand()
}

func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	if ts, ok := s.tokenCache[req.Name]; ok {
		tok, err := ts.Token()
		if err != nil {
			return nil, err
		}
		if !tok.Valid() {
			return nil, err
		}
		res := &pb.GetResponse{
			IdToken: tok.Extra("id_token").(string),
		}
		return res, nil
	}

	c, err := store.NewOIDCCredStore()
	if err != nil {
		return nil, err
	}

	creds, err := c.GetOIDCAuth(req.Name)
	if err != nil {
		return nil, err
	}

	ts := creds.TokenSource(ctx)
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	if !tok.Valid() {
		return nil, err
	}
	// cache token
	s.tokenCache[req.Name] = ts

	res := &pb.GetResponse{
		IdToken: tok.Extra("id_token").(string),
	}
	return res, nil
}

func RunServer() {
	errCh := make(chan error)

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	go func() {
		s := grpc.NewServer()
		pb.RegisterOIDCAgentServer(s, &Server{})
		reflection.Register(s)
		log.WithField("address", *listenAddr).Info("Starting server")
		if err := s.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Warn("Received SIGTERM, exiting gracefully...")
	case err := <-errCh:
		log.WithError(err).Error("Got an error from errCh, exiting gracefully")
	}
}
