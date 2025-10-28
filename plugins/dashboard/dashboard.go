package dashboard

import (
	"encoding/json"
	"log"
	"net/http"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"github.com/miekg/dns"
)

type DashboardPlugin struct {
	cfg     *config.Config
	metrics *metrics.Metrics
	zones   map[string][]dns.RR
}

func (p *DashboardPlugin) Name() string {
	return "Dashboard"
}

func (p *DashboardPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	// This plugin does not handle DNS requests
	return nil
}

func New(cfg *config.Config, metrics *metrics.Metrics) *DashboardPlugin {
	return &DashboardPlugin{
		cfg:     cfg,
		metrics: metrics,
		zones:   make(map[string][]dns.RR),
	}
}

func (p *DashboardPlugin) withBasicAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "astracat" || pass != "astracat" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func (p *DashboardPlugin) Start() {
	if p.cfg.ServerRole != "master" {
		log.Println("Dashboard disabled: server is not in master mode")
		return
	}

	http.HandleFunc("/", p.withBasicAuth(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "internal/dashboard/index.html")
	}))

	http.HandleFunc("/metrics.json", p.withBasicAuth(p.metrics.JSONMetricsHandler))

	http.HandleFunc("/zones", p.withBasicAuth(p.zonesHandler))
	http.HandleFunc("/zones/import", p.withBasicAuth(p.importZoneHandler))
	http.HandleFunc("/zones/export", p.withBasicAuth(p.exportZoneHandler))

	http.HandleFunc("/config", p.withBasicAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			ServerRole string `json:"server-role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		p.cfg.ServerRole = data.ServerRole
		log.Printf("Server role updated to: %s", p.cfg.ServerRole)

		w.WriteHeader(http.StatusOK)
	}))

	log.Println("Starting dashboard server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start dashboard server: %v", err)
	}
}

func (p *DashboardPlugin) zonesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List zones
		var zoneNames []string
		for name := range p.zones {
			zoneNames = append(zoneNames, name)
		}
		json.NewEncoder(w).Encode(zoneNames)
	case http.MethodPost:
		var data struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		p.zones[data.Name] = []dns.RR{}
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		var data struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		delete(p.zones, data.Name)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *DashboardPlugin) importZoneHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, _, err := r.FormFile("zonefile")
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	zoneParser := dns.NewZoneParser(file, "", "")
	for rr, ok := zoneParser.Next(); ok; rr, ok = zoneParser.Next() {
		if err := zoneParser.Err(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		zoneName := rr.Header().Name
		p.zones[zoneName] = append(p.zones[zoneName], rr)
	}

	w.WriteHeader(http.StatusOK)
}

func (p *DashboardPlugin) exportZoneHandler(w http.ResponseWriter, r *http.Request) {
	zoneName := r.URL.Query().Get("zone")
	if zoneName == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	records, ok := p.zones[zoneName]
	if !ok {
		http.Error(w, "Zone not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+zoneName)
	for _, rr := range records {
		w.Write([]byte(rr.String() + "\n"))
	}
}
