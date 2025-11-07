package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/plugins/authoritative"
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"time"
)

type DashboardPlugin struct {
	cfg         *config.Config
	metrics     *metrics.Metrics
	authPlugin  *authoritative.AuthoritativePlugin
}

func (p *DashboardPlugin) Name() string {
	return "Dashboard"
}

func (p *DashboardPlugin) Execute(ctx *plugins.PluginContext, msg *dns.Msg) error {
	// This plugin does not handle DNS requests
	return nil
}

func New(cfg *config.Config, metrics *metrics.Metrics, authPlugin *authoritative.AuthoritativePlugin) *DashboardPlugin {
	return &DashboardPlugin{
		cfg:        cfg,
		metrics:    metrics,
		authPlugin: authPlugin,
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

func (p *DashboardPlugin) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", p.withBasicAuth(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "internal/dashboard/index.html")
	}))

	mux.HandleFunc("/metrics.json", p.withBasicAuth(p.metrics.JSONMetricsHandler))

	mux.HandleFunc("/zones", p.withBasicAuth(p.zonesHandler))
	mux.HandleFunc("/zones/import", p.withBasicAuth(p.importZoneHandler))
	mux.HandleFunc("/zones/export", p.withBasicAuth(p.exportZoneHandler))
	mux.HandleFunc("/zones/", p.withBasicAuth(p.zoneSpecificHandler)) // Renamed for clarity
	mux.HandleFunc("/api/v1/zones", p.apiZonesHandler)

	mux.HandleFunc("/config", p.withBasicAuth(p.configHandler))
}

func (p *DashboardPlugin) Start() {
	if p.cfg.ServerRole != "master" {
		log.Println("Dashboard disabled: server is not in master mode")
		return
	}

	p.RegisterHandlers(http.DefaultServeMux)

	log.Println("Starting dashboard server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start dashboard server: %v", err)
	}
}

func (p *DashboardPlugin) apiZonesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	zoneDTOs := p.authPlugin.GetZoneDTOs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(zoneDTOs)
}

func (p *DashboardPlugin) zonesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		zoneNames := p.authPlugin.GetZoneNames()
		json.NewEncoder(w).Encode(zoneNames)
	case http.MethodPost:
		var data struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if err := p.authPlugin.AddZone(data.Name); err != nil {
			http.Error(w, "Failed to add zone", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var data struct {
			OldName string `json:"oldName"`
			NewName string `json:"newName"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if err := p.authPlugin.UpdateZone(data.OldName, data.NewName); err != nil {
			http.Error(w, "Failed to update zone: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		var data struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if err := p.authPlugin.DeleteZone(data.Name); err != nil {
			http.Error(w, "Failed to delete zone", http.StatusInternalServerError)
			return
		}
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

	file, handler, err := r.FormFile("zonefile")
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a temporary file
	tempFile, err := os.CreateTemp("", "zonefile-*.zone")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())

	// Copy the uploaded file to the temporary file
	if _, err := io.Copy(tempFile, file); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Load the zone from the temporary file
	if err := p.authPlugin.LoadZone(tempFile.Name()); err != nil {
		http.Error(w, "Failed to load zone", http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully imported zone from %s", handler.Filename)
	w.WriteHeader(http.StatusOK)
}

func (p *DashboardPlugin) configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := struct {
			ServerRole        string `json:"server_role"`
			MasterAPIEndpoint string `json:"master_api_endpoint"`
			SyncInterval      int64  `json:"sync_interval"`
		}{
			ServerRole:        p.cfg.ServerRole,
			MasterAPIEndpoint: p.cfg.MasterAPIEndpoint,
			SyncInterval:      int64(p.cfg.SyncInterval.Seconds()),
		}
		json.NewEncoder(w).Encode(data)
	case http.MethodPost:
		var data struct {
			ServerRole        string `json:"server-role"`
			MasterAPIEndpoint string `json:"master-api-endpoint"`
			SyncInterval      int64  `json:"sync-interval"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		p.cfg.ServerRole = data.ServerRole
		p.cfg.MasterAPIEndpoint = data.MasterAPIEndpoint
		p.cfg.SyncInterval = time.Duration(data.SyncInterval) * time.Second

		if err := p.cfg.Save("config.json"); err != nil {
			log.Printf("Error saving configuration: %v", err)
			http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
			return
		}
		log.Printf("Configuration updated and saved")

		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *DashboardPlugin) zoneSpecificHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/zones/"), "/")
	if len(parts) < 1 {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	zoneName := parts[0]

	// Route to the appropriate handler based on the path
	if len(parts) > 1 && parts[1] == "notify" {
		p.notifyHandler(w, r, zoneName)
	} else {
		p.recordsHandler(w, r, zoneName)
	}
}

func (p *DashboardPlugin) notifyHandler(w http.ResponseWriter, r *http.Request, zoneName string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := p.authPlugin.NotifyZoneSlaves(zoneName); err != nil {
		log.Printf("Failed to send NOTIFY for zone %s: %v", zoneName, err)
		http.Error(w, "Failed to send notify: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Successfully sent NOTIFY for zone %s", zoneName)
}

func (p *DashboardPlugin) recordsHandler(w http.ResponseWriter, r *http.Request, zoneName string) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/zones/"), "/")

	switch r.Method {
	case http.MethodGet:
		records, err := p.authPlugin.GetZoneRecords(zoneName)
		if err != nil {
			http.Error(w, "Zone not found", http.StatusNotFound)
			return
		}

		// Convert records to a JSON-friendly format
		var jsonRecords []map[string]interface{}
		for _, record := range records {
			parts := strings.Fields(record.RR.String())
			value := strings.Join(parts[4:], " ")
			jsonRecords = append(jsonRecords, map[string]interface{}{
				"id":    record.ID,
				"name":  record.RR.Header().Name,
				"type":  dns.TypeToString[record.RR.Header().Rrtype],
				"ttl":   record.RR.Header().Ttl,
				"value": value,
			})
		}

		json.NewEncoder(w).Encode(jsonRecords)
	case http.MethodPost:
		if len(parts) < 2 || parts[1] != "records" {
			http.Error(w, "POST should be to /zones/{zoneName}/records", http.StatusBadRequest)
			return
		}
		var data struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			TTL   uint32 `json:"ttl"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", data.Name, data.TTL, data.Type, data.Value))
		if err != nil {
			http.Error(w, "Invalid record", http.StatusBadRequest)
			return
		}

		if _, err := p.authPlugin.AddZoneRecord(zoneName, rr); err != nil {
			http.Error(w, "Failed to add record", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		if len(parts) < 3 || parts[1] != "records" {
			http.Error(w, "PUT should be to /zones/{zoneName}/records/{id}", http.StatusBadRequest)
			return
		}
		recordId, err := strconv.Atoi(parts[2])
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		var data struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			TTL   uint32 `json:"ttl"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", data.Name, data.TTL, data.Type, data.Value))
		if err != nil {
			http.Error(w, "Invalid record", http.StatusBadRequest)
			return
		}

		if err := p.authPlugin.UpdateZoneRecord(zoneName, recordId, rr); err != nil {
			http.Error(w, "Failed to update record", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if len(parts) < 3 || parts[1] != "records" {
			http.Error(w, "DELETE should be to /zones/{zoneName}/records/{id}", http.StatusBadRequest)
			return
		}
		recordId, err := strconv.Atoi(parts[2])
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if err := p.authPlugin.DeleteZoneRecord(zoneName, recordId); err != nil {
			http.Error(w, "Failed to delete record", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *DashboardPlugin) exportZoneHandler(w http.ResponseWriter, r *http.Request) {
	zoneName := r.URL.Query().Get("zone")
	if zoneName == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	records, err := p.authPlugin.GetZoneRecords(zoneName)
	if err != nil {
		http.Error(w, "Zone not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+zoneName)
	for _, record := range records {
		w.Write([]byte(record.RR.String() + "\n"))
	}
}
