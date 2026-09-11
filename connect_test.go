package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDigest = "ad39823476e3a8a6db81f61364d4f25159a2f99c3be280b4507dff2bf140ee37"

func TestConnectPromptsExchangesPersistsAndBinds(t *testing.T) {
	t.Setenv("NULL_ENROLLMENT_TOKEN", "")
	enrollmentToken := "nle_" + strings.Repeat("a", 64)
	workloadToken := "nlw_" + strings.Repeat("b", 64)
	exchanges, bindings := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Null-Organization-ID") != "" || r.Header.Get("X-Null-Project-ID") != "" {
			t.Fatal("client sent caller-controlled tenant scope")
		}
		switch r.URL.Path {
		case "/v1/enrollments/exchange":
			exchanges++
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["enrollment_token"] != enrollmentToken {
				t.Fatal("enrollment token was not exchanged")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"credential":       map[string]any{"credential_id": "credential_test", "execution_id": "exec_test", "subject_id": "workload_test", "expires_at": time.Now().Add(time.Hour)},
				"credential_token": workloadToken,
			})
		case "/v1/executions/exec_test/runtimes":
			bindings++
			if r.Header.Get("Authorization") != "Bearer "+workloadToken {
				t.Fatal("binding did not use exchanged workload credential")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"incarnation":   map[string]any{"ID": "runtime_test", "Provider": "declared", "Model": "model-a", "Harness": "null-cli"},
				"lease":         map[string]any{"ID": "lease_test", "ExpiresAt": time.Now().Add(2 * time.Minute), "FencingEpoch": 1},
				"fencing_epoch": 1, "cursor": 3,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "client.json")
	var output bytes.Buffer
	err := runConnect([]string{"--server", server.URL, "--model", "model-a", "--capability-digest", testDigest, "--config", configPath}, strings.NewReader(enrollmentToken+"\n"), &output)
	if err != nil {
		t.Fatal(err)
	}
	if exchanges != 1 || bindings != 1 {
		t.Fatalf("exchange=%d binding=%d", exchanges, bindings)
	}
	if !strings.Contains(output.String(), "Connected to null.select") || !strings.Contains(output.String(), "Fencing epoch: 1") || strings.Contains(output.String(), workloadToken) {
		t.Fatalf("unexpected output: %s", output.String())
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode=%o", info.Mode().Perm())
	}

	output.Reset()
	if err := runConnect([]string{"--server", server.URL, "--model", "model-a", "--capability-digest", testDigest, "--config", configPath}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if exchanges != 1 || bindings != 2 {
		t.Fatalf("retry exchange=%d binding=%d", exchanges, bindings)
	}
}

func TestConnectRejectsUnsafeOptionsAndCredentialPermissions(t *testing.T) {
	if err := validateConnectOptions("https://user:secret@example.com", "declared", "model", "null-cli", testDigest, "client"); err == nil {
		t.Fatal("URL credentials accepted")
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadClientConfig(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected permission error, got %v", err)
	}
}

func TestVersionDoesNotExposeBuildInternals(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"version"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "null dev\n" {
		t.Fatalf("version output %q", got)
	}
}
