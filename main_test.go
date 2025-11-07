package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/plugins/authoritative"
	"dns-resolver/plugins/dashboard"
	"dns-resolver/plugins/loadbalancer"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_ResolveA(t *testing.T) {
	go main()
	time.Sleep(1 * time.Second)
	client := new(dns.Client)
	msg := new(dns.Msg)
	// Using cloudflare.com as it's a well-known, stable domain.
	msg.SetQuestion("cloudflare.com.", dns.TypeA)

	// The server is running on the default address from config.
	serverAddr := "127.0.0.1:5053"

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		t.Fatalf("Failed to exchange with server: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 0 {
		t.Error("Expected to receive at least one answer")
	}
}

// func TestIntegration_ResolveDNSSEC(t *testing.T) {
// 	go main()
// 	time.Sleep(1 * time.Second)
// 	client := new(dns.Client)
// 	msg := new(dns.Msg)
// 	// Using ripe.net as it's known to be DNSSEC-signed.
// 	msg.SetQuestion("ripe.net.", dns.TypeA)
// 	// Set the DO (DNSSEC OK) bit to request DNSSEC data.
// 	msg.SetEdns0(4096, true)
//
// 	serverAddr := "127.0.0.1:5053"
//
// 	resp, _, err := client.Exchange(msg, serverAddr)
// 	if err != nil {
// 		t.Fatalf("Failed to exchange with server: %v", err)
// 	}
//
// 	if resp.Rcode != dns.RcodeSuccess {
// 		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
// 	}
//
// 	if len(resp.Answer) == 0 {
// 		t.Error("Expected to receive at least one answer")
// 	}
//
// 	// Check for the AD (Authenticated Data) bit in the response.
// 	// This indicates that the resolver was able to validate the data.
// 	// if !resp.AuthenticatedData {
// 	// 	t.Error("Expected Authenticated Data (AD) bit to be set for a DNSSEC-signed domain")
// 	// }
// }

func BenchmarkResolve(b *testing.B) {
	go main()
	time.Sleep(1 * time.Second)
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	serverAddr := "127.0.0.1:5053"

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := client.Exchange(msg, serverAddr)
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func TestApiZoneSynchronization(t *testing.T) {
	// 1. Setup Master Server
	masterCfg := config.NewConfig()
	masterCfg.ServerRole = "master"
	masterZonesFile := "test_master_zones.json"
	// Ensure a clean state before the test
	os.Remove(masterZonesFile)
	defer os.Remove(masterZonesFile)

	masterAuthPlugin := authoritative.New(masterZonesFile)
	masterLbPlugin := loadbalancer.New()
	masterDashboardPlugin := dashboard.New(masterCfg, metrics.NewMetrics(), masterAuthPlugin, masterLbPlugin)

	// Create a new ServeMux for the test server
	mux := http.NewServeMux()
	masterDashboardPlugin.RegisterHandlers(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	// 2. Add data to the master
	zoneName := "example.com."
	err := masterAuthPlugin.AddZone(zoneName)
	require.NoError(t, err)

	rr, err := dns.NewRR("test.example.com. 3600 IN A 1.2.3.4")
	require.NoError(t, err)
	_, err = masterAuthPlugin.AddZoneRecord(zoneName, rr)
	require.NoError(t, err)

	// 3. Setup Slave Server
	slaveCfg := config.NewConfig()
	slaveCfg.ServerRole = "slave"
	slaveCfg.MasterAPIEndpoint = server.URL + "/api/v1/zones"
	slaveZonesFile := "test_slave_zones.json"
	defer os.Remove(slaveZonesFile)

	slaveAuthPlugin := authoritative.New(slaveZonesFile)

	// 4. Trigger synchronization by simulating the slave's API call
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", slaveCfg.MasterAPIEndpoint, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var zoneDTOs []authoritative.ZoneDTO
	err = json.NewDecoder(resp.Body).Decode(&zoneDTOs)
	require.NoError(t, err)

	err = slaveAuthPlugin.ReplaceAllZones(zoneDTOs)
	require.NoError(t, err)

	// 5. Verify the slave's data
	slaveZones := slaveAuthPlugin.GetZoneNames()
	assert.Contains(t, slaveZones, zoneName)

	slaveRecords, err := slaveAuthPlugin.GetZoneRecords(zoneName)
	require.NoError(t, err)
	// There should be 2 records: the default SOA and the A record we added.
	assert.Len(t, slaveRecords, 2)

	foundARecord := false
	for _, rec := range slaveRecords {
		if a, ok := rec.RR.(*dns.A); ok {
			if a.A.String() == "1.2.3.4" {
				foundARecord = true
				break
			}
		}
	}
	assert.True(t, foundARecord, "A record 'test.example.com. A 1.2.3.4' was not found on the slave")
}
