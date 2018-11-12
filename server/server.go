package server

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/protobuf/ptypes"
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
	listenAddr = command.Flag("listen", "Listen address.").Short('l').Default("localhost:1337").String()
)

type Server struct {
	tokenCache map[string]oauth2.TokenSource
	store      store.OIDCCredStore
}

func FullCommand() string {
	return command.FullCommand()
}

func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	creds, err := s.store.GetOIDCAuth(req.Name)
	if err != nil {
		return nil, err
	}

	if ts, ok := s.tokenCache[req.Name]; ok {
		tok, err := ts.Token()
		if err != nil {
			return nil, err
		}
		if !tok.Valid() {
			return nil, err
		}
		idToken := tok.Extra("id_token")
		if idToken == nil {
			idToken = creds.InitialIdToken
		}
		expiry, err := ptypes.TimestampProto(tok.Expiry)
		if err != nil {
			return nil, err
		}
		log.WithField("cred", req.Name).WithField("expire", tok.Expiry).Info("Request")
		res := &pb.GetResponse{
			IdToken:     idToken.(string),
			AccessToken: tok.AccessToken,
			TokenExpiry: expiry,
		}
		return res, nil
	}

	ts := creds.TokenSource(context.Background())
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	if !tok.Valid() {
		return nil, err
	}
	idToken := tok.Extra("id_token")
	if idToken == nil {
		idToken = creds.InitialIdToken
	}
	// cache token
	s.tokenCache[req.Name] = ts

	expiry, err := ptypes.TimestampProto(tok.Expiry)
	if err != nil {
		return nil, err
	}
	log.WithField("cred", req.Name).WithField("expire", tok.Expiry).Info("Request")
	res := &pb.GetResponse{
		IdToken:     idToken.(string),
		AccessToken: tok.AccessToken,
		TokenExpiry: expiry,
	}
	return res, nil
}

func RunServer() {
	errCh := make(chan error)

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s, err := store.NewOIDCCredStore()
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	go func() {
		svc := grpc.NewServer()
		pb.RegisterOIDCAgentServer(svc, &Server{
			tokenCache: make(map[string]oauth2.TokenSource),
			store:      s,
		})
		reflection.Register(svc)
		log.WithField("address", *listenAddr).Info("Starting server")
		if err := svc.Serve(lis); err != nil {
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
