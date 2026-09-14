package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	defaultGateway          = "https://console.null.select/connect"
	maxConnectResponseBytes = 128 * 1024
	maxClientConfigBytes    = 32 * 1024
)

var connectDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	errSavedCredentialExpired    = errors.New("saved workload credential has expired")
	errSavedCredentialIncomplete = errors.New("saved workload credential is incomplete")
)

type clientConfig struct {
	Server                string    `json:"server"`
	CredentialToken       string    `json:"credential_token"`
	CredentialID          string    `json:"credential_id"`
	ExecutionID           string    `json:"execution_id"`
	SubjectID             string    `json:"subject_id"`
	ExpiresAt             time.Time `json:"expires_at"`
	IncarnationID         string    `json:"incarnation_id"`
	ProcessInstance       string    `json:"process_instance"`
	Provider              string    `json:"provider"`
	Model                 string    `json:"model"`
	Harness               string    `json:"harness"`
	CapabilityDigest      string    `json:"capability_digest"`
	BindingIdempotencyKey string    `json:"binding_idempotency_key"`
	FencingEpoch          int64     `json:"fencing_epoch,omitempty"`
}

type exchangeResponse struct {
	Credential struct {
		ID          string    `json:"credential_id"`
		ExecutionID string    `json:"execution_id"`
		SubjectID   string    `json:"subject_id"`
		ExpiresAt   time.Time `json:"expires_at"`
	} `json:"credential"`
	Token string `json:"credential_token"`
}

type bindResponse struct {
	Incarnation struct {
		ID       string `json:"ID"`
		Provider string `json:"Provider"`
		Model    string `json:"Model"`
		Harness  string `json:"Harness"`
	} `json:"incarnation"`
	Lease struct {
		ID            string    `json:"ID"`
		ExecutionID   string    `json:"ExecutionID"`
		IncarnationID string    `json:"IncarnationID"`
		ExpiresAt     time.Time `json:"ExpiresAt"`
		FencingEpoch  int64     `json:"FencingEpoch"`
	} `json:"lease"`
	Epoch     int64  `json:"fencing_epoch"`
	Cursor    int64  `json:"cursor"`
	CapsuleID string `json:"capsule_id"`
	Capsule   struct {
		RecipientID        string `json:"recipient_incarnation_id"`
		ExpectedNextAction string `json:"expected_next_action"`
	} `json:"capsule"`
}

type heartbeatResponse struct {
	Status string `json:"status"`
	Lease  struct {
		ID            string    `json:"ID"`
		ExecutionID   string    `json:"ExecutionID"`
		IncarnationID string    `json:"IncarnationID"`
		ExpiresAt     time.Time `json:"ExpiresAt"`
		FencingEpoch  int64     `json:"FencingEpoch"`
	} `json:"lease"`
}

type gatewayError struct {
	Status  int
	Code    string
	Message string
}

func (e *gatewayError) Error() string {
	if e.Code != "" {
		return e.Code + ": " + e.Message
	}
	return e.Message
}

func runConnect(args []string, input io.Reader, output io.Writer) error {
	return runConnectContext(context.Background(), args, input, output)
}

func runConnectContext(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(output)
	server := flags.String("server", defaultGateway, "null.select connection gateway")
	provider := flags.String("provider", "declared", "runtime provider identity")
	model := flags.String("model", "", "declared model identity")
	harness := flags.String("harness", "null-cli", "runtime harness identity")
	capability := flags.String("capability-digest", "", "SHA-256 capability-set digest")
	clientName := flags.String("client-name", "local agent runtime", "operator-visible client name")
	configPath := flags.String("config", defaultClientConfigPath(), "credential configuration path")
	reEnroll := flags.Bool("re-enroll", false, "replace the saved enrollment for this config path")
	jsonOutput := flags.Bool("json", false, "print the binding response as JSON and exit")
	once := flags.Bool("once", false, "bind once without maintaining the lease")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("connect accepts flags only")
	}
	if err := validateConnectOptions(*server, *provider, *model, *harness, *capability, *clientName); err != nil {
		return err
	}

	token := strings.TrimSpace(os.Getenv("NULL_ENROLLMENT_TOKEN"))
	var config clientConfig
	var err error
	if token != "" || *reEnroll {
		if token == "" {
			token, err = promptEnrollmentToken(input, output)
			if err != nil {
				return err
			}
		}
		config, err = exchangeAndSave(ctx, *server, token, *clientName, *provider, *model, *harness, *capability, *configPath)
	} else {
		config, err = loadClientConfig(*configPath)
		if os.IsNotExist(err) {
			token, err = promptEnrollmentToken(input, output)
			if err == nil {
				config, err = exchangeAndSave(ctx, *server, token, *clientName, *provider, *model, *harness, *capability, *configPath)
			}
		} else if errors.Is(err, errSavedCredentialExpired) {
			if _, writeErr := fmt.Fprintln(output, "Saved workload credential expired; enter a new console enrollment."); writeErr != nil {
				return writeErr
			}
			token, err = promptEnrollmentToken(input, output)
			if err == nil {
				config, err = exchangeAndSave(ctx, *server, token, *clientName, *provider, *model, *harness, *capability, *configPath)
			}
		} else if err == nil && (config.Server != strings.TrimRight(*server, "/") || config.Provider != *provider || config.Model != *model || config.Harness != *harness || config.CapabilityDigest != *capability) {
			return errors.New("saved enrollment is bound to different runtime options; use the original options or --re-enroll")
		}
	}
	if err != nil {
		return fmt.Errorf("prepare workload credential: %w", err)
	}
	response, raw, err := bindEnrolledRuntime(ctx, config)
	if err != nil {
		return fmt.Errorf("bind runtime (credential remains saved for retry): %w", err)
	}
	config.FencingEpoch = response.Epoch
	if err := saveClientConfig(*configPath, config); err != nil {
		return fmt.Errorf("save bound fencing epoch: %w", err)
	}
	if *jsonOutput {
		_, err = output.Write(append(raw, '\n'))
		return err
	}
	_, err = fmt.Fprintf(output, "Connected to null.select\nExecution: %s\nRuntime: %s\nModel: %s/%s\nFencing epoch: %d\nLease expires: %s\nCredential: %s\n",
		config.ExecutionID, response.Incarnation.ID, config.Provider, config.Model, response.Epoch,
		response.Lease.ExpiresAt.Format(time.RFC3339), *configPath)
	if err != nil {
		return err
	}
	if response.CapsuleID != "" {
		if _, err := fmt.Fprintf(output, "Continuation capsule: %s\nNext action: %s\n", response.CapsuleID, response.Capsule.ExpectedNextAction); err != nil {
			return err
		}
	}
	if *once {
		return nil
	}
	return maintainLease(ctx, config, response, output)
}

func promptEnrollmentToken(input io.Reader, output io.Writer) (string, error) {
	if _, err := fmt.Fprint(output, "Enrollment token: "); err != nil {
		return "", err
	}
	var tokenBytes []byte
	var err error
	if file, ok := input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		tokenBytes, err = term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(output)
	} else {
		tokenBytes, err = bufio.NewReader(io.LimitReader(input, 256)).ReadBytes('\n')
		if errors.Is(err, io.EOF) && len(tokenBytes) > 0 {
			err = nil
		}
	}
	if err != nil {
		return "", fmt.Errorf("read enrollment token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if !regexp.MustCompile(`^nle_[0-9a-f]{64}$`).MatchString(token) {
		return "", errors.New("enrollment token must start with nle_ and contain 64 lowercase hexadecimal characters")
	}
	return token, nil
}

func validateConnectOptions(server, provider, model, harness, capability, clientName string) error {
	parsed, err := url.Parse(server)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("--server must be an HTTP URL without credentials, query, or fragment")
	}
	for name, value := range map[string]string{"provider": provider, "model": model, "harness": harness, "client-name": clientName} {
		if strings.TrimSpace(value) == "" || len(value) > 120 {
			return fmt.Errorf("--%s must be between 1 and 120 characters", name)
		}
	}
	if !connectDigest.MatchString(capability) {
		return errors.New("--capability-digest must be a lowercase SHA-256 digest")
	}
	return nil
}

func exchangeAndSave(ctx context.Context, server, enrollmentToken, clientName, provider, model, harness, capability, configPath string) (clientConfig, error) {
	requestBody, _ := json.Marshal(map[string]string{"enrollment_token": enrollmentToken, "client_name": clientName})
	var exchange exchangeResponse
	if _, err := connectRequest(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/v1/enrollments/exchange", "", requestBody, &exchange); err != nil {
		return clientConfig{}, fmt.Errorf("exchange enrollment: %w", err)
	}
	if exchange.Token == "" || exchange.Credential.ID == "" || exchange.Credential.ExecutionID == "" || exchange.Credential.SubjectID == "" || exchange.Credential.ExpiresAt.IsZero() {
		return clientConfig{}, errors.New("exchange enrollment: gateway response is incomplete")
	}
	config := clientConfig{
		Server: strings.TrimRight(server, "/"), CredentialToken: exchange.Token,
		CredentialID: exchange.Credential.ID, ExecutionID: exchange.Credential.ExecutionID,
		SubjectID: exchange.Credential.SubjectID, ExpiresAt: exchange.Credential.ExpiresAt,
		IncarnationID: randomClientID("runtime"), ProcessInstance: randomClientID("process"),
		Provider: provider, Model: model, Harness: harness, CapabilityDigest: capability,
		BindingIdempotencyKey: randomClientID("bind"),
	}
	if err := saveClientConfig(configPath, config); err != nil {
		return clientConfig{}, fmt.Errorf("save workload credential before binding: %w", err)
	}
	return config, nil
}

func bindEnrolledRuntime(ctx context.Context, config clientConfig) (bindResponse, []byte, error) {
	body, _ := json.Marshal(map[string]string{
		"incarnation_id": config.IncarnationID, "provider": config.Provider, "model": config.Model,
		"harness": config.Harness, "process_instance": config.ProcessInstance,
		"capability_digest": config.CapabilityDigest, "idempotency_key": config.BindingIdempotencyKey,
	})
	var response bindResponse
	raw, err := connectRequest(ctx, http.MethodPost, config.Server+"/v1/executions/"+url.PathEscape(config.ExecutionID)+"/runtimes", config.CredentialToken, body, &response)
	if err != nil {
		return bindResponse{}, nil, err
	}
	if response.Incarnation.ID != config.IncarnationID || response.Lease.ID == "" || response.Lease.ExecutionID != config.ExecutionID || response.Lease.IncarnationID != config.IncarnationID || response.Epoch < 1 || response.Lease.FencingEpoch != response.Epoch || response.Lease.ExpiresAt.IsZero() {
		return bindResponse{}, nil, errors.New("gateway binding response is incomplete")
	}
	if response.CapsuleID != "" && response.Capsule.RecipientID != config.IncarnationID {
		return bindResponse{}, nil, errors.New("gateway continuation capsule is not bound to this runtime")
	}
	return response, raw, nil
}

func maintainLease(ctx context.Context, config clientConfig, binding bindResponse, output io.Writer) error {
	return maintainLeaseWith(ctx, config, binding, output, time.Now, waitForContext, renewLease)
}

func maintainLeaseWith(ctx context.Context, config clientConfig, binding bindResponse, output io.Writer, now func() time.Time, wait func(context.Context, time.Duration) error, renew func(context.Context, clientConfig, int64) (heartbeatResponse, error)) error {
	leaseID, expiresAt := binding.Lease.ID, binding.Lease.ExpiresAt
	if _, err := fmt.Fprintln(output, "Lease heartbeat active. Keep this process running; press Ctrl-C to disconnect."); err != nil {
		return err
	}
	delay := renewalDelay(now(), expiresAt)
	for {
		if delay <= 0 || !now().Before(config.ExpiresAt) {
			return errors.New("effect lease can no longer be renewed; create a new enrollment")
		}
		if err := wait(ctx, delay); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				_, writeErr := fmt.Fprintln(output, "Disconnected. Effect authority will expire unless another valid runtime is promoted.")
				return writeErr
			}
			return err
		}
		heartbeat, err := renew(ctx, config, binding.Epoch)
		if err != nil {
			if isTerminalHeartbeatError(err) {
				return fmt.Errorf("effect authority ended: %w", err)
			}
			remaining := expiresAt.Sub(now())
			if remaining <= 0 {
				return fmt.Errorf("effect lease expired while heartbeat was unavailable: %w", err)
			}
			delay = retryDelay(remaining)
			continue
		}
		if heartbeat.Status != "renewed" || heartbeat.Lease.ID != leaseID || heartbeat.Lease.ExecutionID != config.ExecutionID || heartbeat.Lease.IncarnationID != config.IncarnationID || heartbeat.Lease.FencingEpoch != binding.Epoch || !heartbeat.Lease.ExpiresAt.After(now()) {
			return errors.New("heartbeat response did not match the bound runtime lease")
		}
		expiresAt = heartbeat.Lease.ExpiresAt
		delay = renewalDelay(now(), expiresAt)
	}
}

func renewLease(ctx context.Context, config clientConfig, epoch int64) (heartbeatResponse, error) {
	body, _ := json.Marshal(map[string]any{"incarnation_id": config.IncarnationID, "fencing_epoch": epoch})
	var response heartbeatResponse
	_, err := connectRequest(ctx, http.MethodPost, config.Server+"/v1/executions/"+url.PathEscape(config.ExecutionID)+"/heartbeat", config.CredentialToken, body, &response)
	return response, err
}

func renewalDelay(now, expiresAt time.Time) time.Duration {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	delay := remaining / 3
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func retryDelay(remaining time.Duration) time.Duration {
	delay := remaining / 4
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

func waitForContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isTerminalHeartbeatError(err error) bool {
	var failure *gatewayError
	if !errors.As(err, &failure) {
		return false
	}
	return failure.Status >= 400 && failure.Status < 500 && failure.Status != http.StatusTooManyRequests
}

func connectRequest(ctx context.Context, method, target, bearerToken string, body []byte, result any) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "null-cli/"+version)
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	response, err := (&http.Client{Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxConnectResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(responseBody) > maxConnectResponseBytes || !json.Valid(responseBody) {
		return nil, errors.New("gateway returned invalid or oversized JSON")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(responseBody, &failure)
		if failure.Message == "" {
			failure.Message = fmt.Sprintf("gateway returned HTTP %d", response.StatusCode)
		}
		return nil, &gatewayError{Status: response.StatusCode, Code: failure.Code, Message: failure.Message}
	}
	if err := json.Unmarshal(responseBody, result); err != nil {
		return nil, errors.New("gateway response did not match the client contract")
	}
	return responseBody, nil
}

func defaultClientConfigPath() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", ".null-select-client.json")
	}
	return filepath.Join(directory, "null-select", "client.json")
}

func saveClientConfig(path string, config clientConfig) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".client-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(config); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func loadClientConfig(path string) (clientConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return clientConfig{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return clientConfig{}, errors.New("credential file permissions must be 0600")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return clientConfig{}, err
	}
	if len(body) > maxClientConfigBytes {
		return clientConfig{}, errors.New("credential file exceeds 32 KiB")
	}
	var config clientConfig
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return clientConfig{}, err
	}
	if config.CredentialToken == "" || config.ExecutionID == "" || config.IncarnationID == "" || config.BindingIdempotencyKey == "" || config.ExpiresAt.IsZero() {
		return clientConfig{}, errSavedCredentialIncomplete
	}
	if !time.Now().Before(config.ExpiresAt) {
		return clientConfig{}, errSavedCredentialExpired
	}
	return config, nil
}

func randomClientID(prefix string) string {
	var data [12]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(data[:])
}
