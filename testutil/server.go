package testutil

import (
	"io"
	"net"
	"net/http"
	"unicode/utf8"
)

// EchoHandler answers a request with its own headers and body.
// Responds with 400 Bad Request if the body is not valid UTF-8.
func EchoHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	if len(body) > 0 && !utf8.Valid(body) {
		http.Error(w, "body is not valid UTF-8", http.StatusBadRequest)
		return
	}

	for key, values := range r.Header {
		for _, val := range values {
			w.Header().Add(key, val)
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Server represents a running test echo server.
type Server struct {
	server   *http.Server
	listener net.Listener
	addr     net.Addr
}

// LaunchServer launches an echo server on localhost and returns its running instance.
func LaunchServer() (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(EchoHandler),
	}

	s := &Server{
		server:   srv,
		listener: listener,
		addr:     listener.Addr(),
	}

	go func() {
		_ = srv.Serve(listener)
	}()

	return s, nil
}

// Addr returns the server's listening network address.
func (s *Server) Addr() net.Addr {
	return s.addr
}

// Close shuts down the test server.
func (s *Server) Close() error {
	return s.server.Close()
}
