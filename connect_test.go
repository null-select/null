package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"incarnation":   map[string]any{"ID": body["incarnation_id"], "Provider": "declared", "Model": "model-a", "Harness": "null-cli"},
				"lease":         map[string]any{"ID": "lease_test", "ExecutionID": "exec_test", "IncarnationID": body["incarnation_id"], "ExpiresAt": time.Now().Add(2 * time.Minute), "FencingEpoch": 1},
				"fencing_epoch": 1, "cursor": 3,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "client.json")
	var output bytes.Buffer
	err := runConnect([]string{"--server", server.URL, "--model", "model-a", "--capability-digest", testDigest, "--config", configPath, "--once"}, strings.NewReader(enrollmentToken+"\n"), &output)
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
	if err := runConnect([]string{"--server", server.URL, "--model", "model-a", "--capability-digest", testDigest, "--config", configPath, "--once"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if exchanges != 1 || bindings != 2 {
		t.Fatalf("retry exchange=%d binding=%d", exchanges, bindings)
	}
}

func TestLeaseHeartbeatContinuesUntilContextCancellation(t *testing.T) {
	now := time.Now().UTC()
	config := clientConfig{ExecutionID: "exec_test", IncarnationID: "runtime_test", ExpiresAt: now.Add(time.Hour), CredentialToken: "nlw_" + strings.Repeat("a", 64)}
	var binding bindResponse
	binding.Epoch = 3
	binding.Lease.ID = "lease_test"
	binding.Lease.ExpiresAt = now.Add(2 * time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	renewals := 0
	renew := func(context.Context, clientConfig, int64) (heartbeatResponse, error) {
		renewals++
		var response heartbeatResponse
		response.Status = "renewed"
		response.Lease.ID = "lease_test"
		response.Lease.ExecutionID = "exec_test"
		response.Lease.IncarnationID = "runtime_test"
		response.Lease.FencingEpoch = 3
		response.Lease.ExpiresAt = now.Add(time.Duration(2+renewals) * time.Minute)
		if renewals == 3 {
			cancel()
		}
		return response, nil
	}
	wait := func(ctx context.Context, _ time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	var output bytes.Buffer
	if err := maintainLeaseWith(ctx, config, binding, &output, func() time.Time { return now }, wait, renew); err != nil {
		t.Fatal(err)
	}
	if renewals != 3 || !strings.Contains(output.String(), "Lease heartbeat active") || !strings.Contains(output.String(), "Disconnected") || strings.Contains(output.String(), config.CredentialToken) {
		t.Fatalf("unexpected heartbeat result renewals=%d output=%q", renewals, output.String())
	}
}

func TestLeaseHeartbeatRetriesTransportFailureButStopsOnFencing(t *testing.T) {
	now := time.Now().UTC()
	config := clientConfig{ExecutionID: "exec_test", IncarnationID: "runtime_test", ExpiresAt: now.Add(time.Hour)}
	var binding bindResponse
	binding.Epoch = 1
	binding.Lease.ID = "lease_test"
	binding.Lease.ExpiresAt = now.Add(2 * time.Minute)
	calls := 0
	renew := func(context.Context, clientConfig, int64) (heartbeatResponse, error) {
		calls++
		if calls == 1 {
			return heartbeatResponse{}, errors.New("temporary transport loss")
		}
		return heartbeatResponse{}, &gatewayError{Status: http.StatusConflict, Code: "stale_fencing_epoch", Message: "runtime epoch is stale"}
	}
	wait := func(context.Context, time.Duration) error { return nil }
	err := maintainLeaseWith(context.Background(), config, binding, io.Discard, func() time.Time { return now }, wait, renew)
	if err == nil || !strings.Contains(err.Error(), "effect authority ended") || !strings.Contains(err.Error(), "stale_fencing_epoch") || calls != 2 {
		t.Fatalf("unexpected terminal heartbeat result calls=%d err=%v", calls, err)
	}
}

func TestHeartbeatCadenceRenewsWellBeforeExpiry(t *testing.T) {
	now := time.Now()
	if got := renewalDelay(now, now.Add(2*time.Minute)); got != 30*time.Second {
		t.Fatalf("two-minute lease delay=%s", got)
	}
	if got := retryDelay(40 * time.Second); got != 5*time.Second {
		t.Fatalf("retry delay=%s", got)
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
