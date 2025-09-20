package server

import (
	"log"

	"dns-resolver/internal/config"
	"github.com/miekg/dns"
)

// Server holds the server state.
type Server struct {
	config  *config.Config
	handler dns.Handler
}

// NewServer creates a new server.
func NewServer(cfg *config.Config) *Server {
	s := &Server{
		config: cfg,
	}
	s.handler = dns.HandlerFunc(s.handleRequest)
	return s
}

// ListenAndServe starts the DNS server.
func (s *Server) ListenAndServe() {
	go s.startListener("udp")
	go s.startListener("tcp")

	log.Printf("ASTRACAT DNS Resolver is running on %s", s.config.ListenAddr)
	select {} // Block forever
}

func (s *Server) startListener(net string) {
	server := &dns.Server{Addr: s.config.ListenAddr, Net: net, Handler: s.handler}
	log.Printf("Starting %s listener on %s", net, s.config.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start %s listener: %s", net, err)
	}
}

// handleRequest is the default request handler. It returns a failure message.
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeServerFailure
	w.WriteMsg(m)
}

// SetHandler allows replacing the default handler.
// This will be used to inject the resolver logic later.
func (s *Server) SetHandler(handler dns.Handler) {
	s.handler = handler
}
