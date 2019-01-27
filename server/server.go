package server

import (
	"context"
	"net"
	"os"
	"os/signal"
	"path/filepath"
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
	command    = kingpin.Command("server", "Start server agent")
	listenAddr = command.Flag("listen", "Listen address.").Short('l').Default("localhost:1337").String()
)

// Server gRPC server struct
type Server struct {
	tokenCache map[string]oauth2.TokenSource
	store      store.OIDCCredStore
}

// FullCommand return command line string
func FullCommand() string {
	return command.FullCommand()
}

func (s *Server) retriveToken(name string, ts oauth2.TokenSource, cred *store.OIDCAuth) (*pb.GetResponse, error) {
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	if !tok.Valid() {
		return nil, err
	}
	idToken := tok.Extra("id_token")
	if idToken == nil {
		idToken = cred.InitialIdToken
	}
	expiry, err := ptypes.TimestampProto(tok.Expiry)
	if err != nil {
		return nil, err
	}
	log.WithField("cred", name).WithField("expire", tok.Expiry).Info("Request")
	return &pb.GetResponse{
		IdToken:     idToken.(string),
		AccessToken: tok.AccessToken,
		TokenExpiry: expiry,
	}, nil
}

//Get will get credential from store and cache if found
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	cred, err := s.store.GetOIDCAuth(req.Name)
	if err != nil {
		return nil, err
	}

	if ts, ok := s.tokenCache[req.Name]; ok {
		return s.retriveToken(req.Name, ts, cred)
	}

	ts := cred.TokenSource(context.Background())
	res, err := s.retriveToken(req.Name, ts, cred)
	if err != nil {
		return nil, err
	}
	//cache token
	s.tokenCache[req.Name] = ts
	return res, nil
}

// RunServer starts a GRPC server
func RunServer() {
	errCh := make(chan error)

	sock := filepath.Join(os.Getenv("HOME"), ".oidc-agent.sock")
	// remove if already existing
	os.Remove(sock)
	lis, err := net.Listen("unix", sock)
	if err != nil {
		log.Warnf("falling back to tcp: %s", *listenAddr)
		lis, err = net.Listen("tcp", *listenAddr)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
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
		log.WithField("address", lis.Addr().String()).Info("Starting server")
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
