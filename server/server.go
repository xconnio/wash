package server

import (
	"fmt"
	"io"
	"log"

	"github.com/xconnio/xconn-go"
)

type Server struct {
	router  *xconn.Router
	server  *xconn.Server
	closer  io.Closer
	realm   string
	address string
}

func NewServer(realm, address string) (*Server, error) {
	router := xconn.NewRouter()
	router.AddRealm(realm)

	server := xconn.NewServer(router, nil, nil)

	return &Server{
		router:  router,
		server:  server,
		realm:   realm,
		address: address,
	}, nil
}

func (s *Server) Start() error {
	closer, err := s.server.ListenAndServeRawSocket(xconn.NetworkTCP, s.address)
	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}
	s.closer = closer
	log.Printf("WAMP server started on %s", s.address)
	return nil
}

func (s *Server) Stop() error {
	if s.closer != nil {
		if err := s.closer.Close(); err != nil {
			return err
		}
	}
	if s.router != nil {
		s.router.Close()
	}
	return nil
}

func (s *Server) Router() *xconn.Router {
	return s.router
}

func (s *Server) Realm() string {
	return s.realm
}

func (s *Server) Address() string {
	return s.address
}
