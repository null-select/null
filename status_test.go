package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatusReportsPersistedAuthorityWithoutCredentialDisclosure(t *testing.T) {
	credential := "nlw_" + strings.Repeat("a", 64)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	leaseExpires := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/status" || r.Header.Get("Authorization") != "Bearer "+credential {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Null-Organization-ID") != "" || r.Header.Get("X-Null-Project-ID") != "" {
			t.Fatal("CLI sent tenant authority")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["incarnation_id"] != "runtime_test" || body["fencing_epoch"] != float64(1) {
			t.Fatalf("unexpected body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(workloadStatusResponse{
			ExecutionID: "exec_test", ExecutionState: "running", IncarnationID: "runtime_test", FencingEpoch: 1, IncarnationState: "current",
			CanonicalIncarnationID: "runtime_test", CanonicalFencingEpoch: 1, Provider: "declared", Model: "model-a", Harness: "null-cli",
			CapabilityDigest: testDigest, Authority: "active", LeaseExpiresAt: &leaseExpires, CredentialExpiresAt: expires, ReadyForConsequentialWork: true,
		})
	}))
	defer server.Close()
	configPath := filepath.Join(t.TempDir(), "client.json")
	if err := saveClientConfig(configPath, diagnosticTestConfig(server.URL, credential, expires)); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"status", "--config", configPath}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Authority: active") || !strings.Contains(output.String(), "Ready for consequential work: yes") || strings.Contains(output.String(), credential) {
		t.Fatalf("unexpected status output: %s", output.String())
	}
}

func TestDoctorTreatsRecoveryHoldAsSuccessfulDiagnosis(t *testing.T) {
	credential := "nlw_" + strings.Repeat("b", 64)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(workloadStatusResponse{
			ExecutionID: "exec_test", ExecutionState: "recovery_hold", IncarnationID: "runtime_test", FencingEpoch: 1,
			CanonicalIncarnationID: "runtime_test", CanonicalFencingEpoch: 1, Authority: "frozen",
			CredentialExpiresAt: expires, UnresolvedActions: 1, ContinuationBlocked: true,
		})
	}))
	defer server.Close()
	configPath := filepath.Join(t.TempDir(), "client.json")
	if err := saveClientConfig(configPath, diagnosticTestConfig(server.URL, credential, expires)); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"doctor", "--config", configPath}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "[HOLD] effect_authority") || !strings.Contains(output.String(), "[HOLD] continuation") || !strings.Contains(output.String(), "Ready for consequential work: no") {
		t.Fatalf("unexpected doctor output: %s", output.String())
	}
}

func TestStatusRejectsContradictoryGatewayResponse(t *testing.T) {
	credential := "nlw_" + strings.Repeat("c", 64)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(workloadStatusResponse{
			ExecutionID: "exec_test", IncarnationID: "runtime_test", FencingEpoch: 1, CanonicalFencingEpoch: 2,
			Authority: "fenced", CredentialExpiresAt: expires, ReadyForConsequentialWork: true,
		})
	}))
	defer server.Close()
	configPath := filepath.Join(t.TempDir(), "client.json")
	config := diagnosticTestConfig(server.URL, credential, expires)
	config.FencingEpoch = 1
	if err := saveClientConfig(configPath, config); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{"status", "--config", configPath}, strings.NewReader(""), &output)
	if err == nil || !strings.Contains(err.Error(), "contradictory authority") {
		t.Fatalf("expected contradictory authority error, got %v", err)
	}
}

func diagnosticTestConfig(server, credential string, expires time.Time) clientConfig {
	return clientConfig{
		Server: server, CredentialToken: credential, CredentialID: "credential_test", ExecutionID: "exec_test", SubjectID: "workload_test", ExpiresAt: expires,
		IncarnationID: "runtime_test", ProcessInstance: "process_test", Provider: "declared", Model: "model-a", Harness: "null-cli",
		CapabilityDigest: testDigest, BindingIdempotencyKey: "bind_test", FencingEpoch: 1,
	}
}
