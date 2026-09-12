package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// EnrichedResult holds resolution and threat data for one discovered subdomain.
type EnrichedResult struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips"`
	ASN    string   `json:"asn"`
	CIDR   string   `json:"cidr"`
	Ports  []int    `json:"ports"`
	CVEs   []string `json:"cves"`
}

type shodanInternetDB struct {
	Ports     []int    `json:"ports"`
	Vulns     []string `json:"vulns"`
	Hostnames []string `json:"hostnames"`
}

type ripeRoutingData struct {
	Data struct {
		Routes []struct {
			Prefix string `json:"prefix"`
			Origin string `json:"origin"`
			InBGP  bool   `json:"in_bgp"`
		} `json:"routes"`
	} `json:"data"`
}

// enrichSubdomains resolves each hostname via net.LookupHost, then queries
// Shodan InternetDB and RIPE Stat for the first public IP found.
func enrichSubdomains(subdomains []string) []EnrichedResult {
	client := &http.Client{Timeout: 10 * time.Second}
	out := make([]EnrichedResult, 0, len(subdomains))

	for _, sub := range subdomains {
		er := EnrichedResult{
			Domain: sub,
			IPs:    []string{},
			Ports:  []int{},
			CVEs:   []string{},
		}

		ips, err := net.LookupHost(sub)
		if err != nil || len(ips) == 0 {
			out = append(out, er)
			continue
		}
		er.IPs = ips

		// Pick first non-private IP for external enrichment
		publicIP := ""
		for _, ip := range ips {
			if !isPrivateIP(ip) {
				publicIP = ip
				break
			}
		}
		if publicIP == "" {
			out = append(out, er)
			continue
		}

		if sdb := queryShodanInternetDB(client, publicIP); sdb != nil {
			if sdb.Ports != nil {
				er.Ports = sdb.Ports
			}
			if sdb.Vulns != nil {
				er.CVEs = sdb.Vulns
			}
		}

		er.ASN, er.CIDR = queryRIPEStat(client, publicIP)
		out = append(out, er)
	}
	return out
}

func queryShodanInternetDB(client *http.Client, ip string) *shodanInternetDB {
	req, err := http.NewRequest("GET", "https://internetdb.shodan.io/"+ip, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "ctrecon/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var result shodanInternetDB
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return &result
}

// queryRIPEStat calls RIPE Stat prefix-routing-consistency and extracts the
// announcing prefix ASN and CIDR. Returns empty strings on any failure.
func queryRIPEStat(client *http.Client, ip string) (asn, cidr string) {
	u := "https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=" + ip
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "ctrecon/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", ""
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", ""
	}
	var result ripeRoutingData
	if err := json.Unmarshal(data, &result); err != nil {
		return "", ""
	}

	// Prefer a route that is active in BGP
	for _, route := range result.Data.Routes {
		if route.InBGP {
			return fmt.Sprintf("AS%s", route.Origin), route.Prefix
		}
	}
	if len(result.Data.Routes) > 0 {
		r := result.Data.Routes[0]
		return fmt.Sprintf("AS%s", r.Origin), r.Prefix
	}
	return "", ""
}

// isPrivateIP returns true for RFC-1918, loopback, and link-local addresses.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidrStr := range privateRanges {
		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// writeEnriched serialises enrichment results as an indented JSON array.
func writeEnriched(w io.Writer, results []EnrichedResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
