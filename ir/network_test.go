package ir

import (
	"encoding/json"
	"testing"
)

func TestNetworkInfo_Fields(t *testing.T) {
	network := NetworkInfo{
		Host:      "api.example.com",
		Ports:     []int{443, 8443},
		Protocols: []string{"HTTPS", "gRPC"},
		Zone:      "dmz",
		CIDR:      "10.0.1.0/24",
		Cloud: &CloudInfo{
			Provider: "aws",
			Region:   "us-east-1",
			VPC:      "vpc-production",
			Subnet:   "subnet-public-1",
		},
	}

	if network.Host != "api.example.com" {
		t.Errorf("Host = %s, want api.example.com", network.Host)
	}
	if len(network.Ports) != 2 {
		t.Errorf("Ports length = %d, want 2", len(network.Ports))
	}
	if network.Ports[0] != 443 {
		t.Errorf("Ports[0] = %d, want 443", network.Ports[0])
	}
	if len(network.Protocols) != 2 {
		t.Errorf("Protocols length = %d, want 2", len(network.Protocols))
	}
	if network.Zone != "dmz" {
		t.Errorf("Zone = %s, want dmz", network.Zone)
	}
	if network.CIDR != "10.0.1.0/24" {
		t.Errorf("CIDR = %s, want 10.0.1.0/24", network.CIDR)
	}
	if network.Cloud == nil {
		t.Fatal("Cloud is nil, want non-nil")
	}
	if network.Cloud.Provider != "aws" {
		t.Errorf("Cloud.Provider = %s, want aws", network.Cloud.Provider)
	}
}

func TestCloudInfo_Fields(t *testing.T) {
	cloud := CloudInfo{
		Provider:   "gcp",
		Region:     "us-central1",
		VPC:        "vpc-main",
		Subnet:     "subnet-private",
		ResourceID: "projects/my-project/instances/my-instance",
	}

	if cloud.Provider != "gcp" {
		t.Errorf("Provider = %s, want gcp", cloud.Provider)
	}
	if cloud.Region != "us-central1" {
		t.Errorf("Region = %s, want us-central1", cloud.Region)
	}
	if cloud.VPC != "vpc-main" {
		t.Errorf("VPC = %s, want vpc-main", cloud.VPC)
	}
	if cloud.Subnet != "subnet-private" {
		t.Errorf("Subnet = %s, want subnet-private", cloud.Subnet)
	}
	if cloud.ResourceID != "projects/my-project/instances/my-instance" {
		t.Errorf("ResourceID = %s, want projects/my-project/instances/my-instance", cloud.ResourceID)
	}
}

func TestNetworkInfo_JSON(t *testing.T) {
	network := NetworkInfo{
		Host:      "db.internal",
		Ports:     []int{5432},
		Protocols: []string{"PostgreSQL"},
		Zone:      "internal",
		Cloud: &CloudInfo{
			Provider: "aws",
			Region:   "us-west-2",
			VPC:      "vpc-data",
		},
	}

	data, err := json.Marshal(network)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed NetworkInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Host != network.Host {
		t.Errorf("Host = %s, want %s", parsed.Host, network.Host)
	}
	if len(parsed.Ports) != 1 || parsed.Ports[0] != 5432 {
		t.Errorf("Ports = %v, want [5432]", parsed.Ports)
	}
	if parsed.Cloud == nil || parsed.Cloud.Provider != "aws" {
		t.Errorf("Cloud.Provider = %v, want aws", parsed.Cloud)
	}
}

func TestElement_WithNetwork(t *testing.T) {
	element := Element{
		ID:    "api-server",
		Label: "API Server",
		Type:  "process",
		Network: &NetworkInfo{
			Host:      "api.example.com",
			Ports:     []int{443},
			Protocols: []string{"HTTPS"},
			Zone:      "dmz",
		},
		AssetIDs: []string{"asset-api", "asset-code"},
	}

	if element.Network == nil {
		t.Fatal("Network is nil, want non-nil")
	}
	if element.Network.Host != "api.example.com" {
		t.Errorf("Network.Host = %s, want api.example.com", element.Network.Host)
	}
	if len(element.AssetIDs) != 2 {
		t.Errorf("AssetIDs length = %d, want 2", len(element.AssetIDs))
	}
}
