package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/resolver"
	"github.com/miekg/dns"
)

var msgPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}
// Server holds the server state.
type Server struct {
	config        *config.Config
	handler       dns.Handler
	metrics       *metrics.Metrics
	resolver      resolver.ResolverInterface
	pluginManager *plugins.PluginManager
}

// NewServer creates a new server.
func NewServer(cfg *config.Config, m *metrics.Metrics, res resolver.ResolverInterface, pm *plugins.PluginManager) *Server {
	s := &Server{
		config:        cfg,
		metrics:       m,
		resolver:      res,
		pluginManager: pm,
	}
	s.buildAndSetHandler()
	return s
}

func (s *Server) buildAndSetHandler() {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) > 0 {
			s.metrics.RecordQueryType(dns.TypeToString[r.Question[0].Qtype])
		}

		// Execute request plugins
		pluginCtx := &plugins.PluginContext{ResponseWriter: w}
		s.pluginManager.ExecutePlugins(pluginCtx, r)

		if pluginCtx.Stop {
			return
		}

		req := msgPool.Get().(*dns.Msg)
		defer func() {
			*req = dns.Msg{}
			msgPool.Put(req)
		}()

		req.SetQuestion(r.Question[0].Name, r.Question[0].Qtype)
		req.RecursionDesired = true
		req.SetEdns0(4096, true)

		ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
		defer cancel()

		msg, err := s.resolver.Resolve(ctx, req)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", req.Question[0].Name, err)
			s.metrics.RecordResponseCode(dns.RcodeToString[dns.RcodeServerFailure])
			dns.HandleFailed(w, r)
			return
		}

		s.metrics.RecordResponseCode(dns.RcodeToString[msg.Rcode])
		msg.Id = r.Id

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})
	s.handler = s.metricsWrapper(handler)
}

// ListenAndServe starts the DNS server.
func (s *Server) ListenAndServe() {
	go s.startListener("udp")
	go s.startListener("tcp")

	if s.config.DoTAddr != "" && s.config.CertFile != "" && s.config.KeyFile != "" {
		go s.startDoT()
	}

	if s.config.DoHAddr != "" && s.config.CertFile != "" && s.config.KeyFile != "" {
		go s.startDoH()
	}

	log.Printf("ASTRACAT DNS Resolver is running on %s", s.config.ListenAddr)
	select {} // Block forever
}

func (s *Server) startListener(net string) {
	server := &dns.Server{Addr: s.config.ListenAddr, Net: net, Handler: s.handler}
	log.Printf("Starting %s listener on %s", net, s.config.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to start %s listener: %s", net, err)
	}
}

func (s *Server) startDoT() {
	cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
	if err != nil {
		log.Printf("Failed to load certificates for DoT: %s", err)
		return
	}

	server := &dns.Server{
		Addr:    s.config.DoTAddr,
		Net:     "tcp-tls",
		Handler: s.handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Printf("Starting DoT listener on %s", s.config.DoTAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to start DoT listener: %s", err)
	}
}

func (s *Server) startDoH() {
	log.Printf("Starting DoH listener on %s", s.config.DoHAddr)
	http.HandleFunc("/dns-query", s.handleDoH)
	if err := http.ListenAndServeTLS(s.config.DoHAddr, s.config.CertFile, s.config.KeyFile, nil); err != nil {
		log.Printf("Failed to start DoH listener: %s", err)
	}
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error

	if r.Method == http.MethodGet {
		query := r.URL.Query().Get("dns")
		if query == "" {
			http.Error(w, "Missing dns query parameter", http.StatusBadRequest)
			return
		}
		// Decode base64url
		body, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(query)
		if err != nil {
			http.Error(w, "Failed to decode DNS query", http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		body, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest)
		return
	}

	// Internal handler logic - use the same handler as UDP/TCP to ensure metrics and plugins are run
	s.handler.ServeDNS(&dohResponseWriter{w: w, r: r}, msg)
}

type dohResponseWriter struct {
	dns.ResponseWriter
	w http.ResponseWriter
	r *http.Request
}

func (d *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	d.w.Header().Set("Content-Type", "application/dns-message")
	// Set standard DoH headers
	d.w.Header().Set("Cache-Control", "max-age=0")
	_, err = d.w.Write(b)
	return err
}

func (d *dohResponseWriter) Write(b []byte) (int, error) {
	return d.w.Write(b)
}

func (d *dohResponseWriter) LocalAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	return addr
}

func (d *dohResponseWriter) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:0")
	return addr
}
func (d *dohResponseWriter) Close() error        { return nil }
func (d *dohResponseWriter) TsigStatus() error    { return nil }
func (d *dohResponseWriter) TsigTimersOnly(bool)  {}
func (d *dohResponseWriter) Hijack()              {}

// metricsWrapper is a middleware that increments the query counter.
func (s *Server) metricsWrapper(h dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.metrics.IncrementQueries()
		h.ServeDNS(w, r)
	})
}
