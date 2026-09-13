package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitHubLabelUsesSavedScopedAuthority(t *testing.T) {
	var received map[string]any
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/connect/v1/executions/exec_1/github/pull-request-labels" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer nlw_"+strings.Repeat("a", 64) || r.Header.Get("User-Agent") == "" {
			t.Fatalf("workload authorization missing: %v", r.Header)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(githubResult{ActionID: "action_1", AttemptID: "attempt_1", Outcome: "confirmed", AttemptState: "verified", Finding: "present"})
	}))
	defer target.Close()
	path := filepath.Join(t.TempDir(), "client.json")
	writeGitHubConfig(t, path, target.URL+"/connect", githubCapabilityDigest)
	var output bytes.Buffer
	err := runGitHubContext(context.Background(), []string{"label", "--owner", "null-select", "--repo", "demo", "--pr", "7", "--label", "continuity-verified", "--idempotency-key", "stable-1", "--config", path}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if received["incarnation_id"] != "runtime_1" || received["fencing_epoch"] != float64(3) || received["idempotency_key"] != "stable-1" || received["owner"] != "null-select" || received["repository"] != "demo" || received["pull_request"] != float64(7) || received["label"] != "continuity-verified" {
		t.Fatalf("unexpected request body %+v", received)
	}
	if !strings.Contains(output.String(), "State: verified") || !strings.Contains(output.String(), "Authoritative finding: present") {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestGitHubObserveUsesVerifierRoute(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connect/v1/github/attempts/attempt_1/observe" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(githubResult{ActionID: "action_1", AttemptID: "attempt_1", AttemptState: "reconciled_present", Finding: "present"})
	}))
	defer target.Close()
	path := filepath.Join(t.TempDir(), "client.json")
	writeGitHubConfig(t, path, target.URL+"/connect", githubCapabilityDigest)
	var output bytes.Buffer
	if err := runGitHubContext(context.Background(), []string{"observe", "--attempt", "attempt_1", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "State: reconciled_present") || !strings.Contains(output.String(), "Finding: present") {
		t.Fatalf("unexpected output %q", output.String())
	}
}

func TestGitHubCommandFailsBeforeNetworkForWrongCapability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	writeGitHubConfig(t, path, "https://example.invalid/connect", strings.Repeat("b", 64))
	err := runGitHubContext(context.Background(), []string{"label", "--owner", "null-select", "--repo", "demo", "--pr", "7", "--label", "safe", "--idempotency-key", "stable", "--config", path}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "runtime capability does not admit GitHub labels") {
		t.Fatalf("unexpected error %v", err)
	}
}

func writeGitHubConfig(t *testing.T, path, server, capability string) {
	t.Helper()
	err := saveClientConfig(path, clientConfig{Server: server, CredentialToken: "nlw_" + strings.Repeat("a", 64), CredentialID: "credential_1", ExecutionID: "exec_1", SubjectID: "workload_1", ExpiresAt: time.Now().Add(time.Hour), IncarnationID: "runtime_1", ProcessInstance: "process_1", Provider: "declared", Model: "deterministic", Harness: "null-cli", CapabilityDigest: capability, BindingIdempotencyKey: "bind_1", FencingEpoch: 3})
	if err != nil {
		t.Fatal(err)
	}
}
