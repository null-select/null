package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type workloadStatusResponse struct {
	ExecutionID               string     `json:"execution_id"`
	ExecutionState            string     `json:"execution_state"`
	IncarnationID             string     `json:"incarnation_id"`
	FencingEpoch              int64      `json:"fencing_epoch"`
	IncarnationState          string     `json:"incarnation_state"`
	CanonicalIncarnationID    string     `json:"canonical_incarnation_id"`
	CanonicalFencingEpoch     int64      `json:"canonical_fencing_epoch"`
	Provider                  string     `json:"provider"`
	Model                     string     `json:"model"`
	Harness                   string     `json:"harness"`
	CapabilityDigest          string     `json:"capability_digest"`
	Authority                 string     `json:"authority"`
	LeaseExpiresAt            *time.Time `json:"lease_expires_at,omitempty"`
	CredentialExpiresAt       time.Time  `json:"credential_expires_at"`
	UnresolvedActions         int        `json:"unresolved_actions"`
	ContinuationBlocked       bool       `json:"continuation_blocked"`
	ReadyForConsequentialWork bool       `json:"ready_for_consequential_work"`
}

type doctorReport struct {
	Healthy                   bool                   `json:"healthy"`
	ReadyForConsequentialWork bool                   `json:"ready_for_consequential_work"`
	Checks                    []doctorCheck          `json:"checks"`
	Status                    workloadStatusResponse `json:"status"`
}

type doctorCheck struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Message string `json:"message"`
}

func runStatusContext(ctx context.Context, args []string, output io.Writer) error {
	configPath, jsonOutput, err := diagnosticFlags("status", args, output)
	if err != nil {
		return err
	}
	config, err := loadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("load workload credential: %w", err)
	}
	status, raw, err := fetchWorkloadStatus(ctx, config)
	if err != nil {
		return fmt.Errorf("fetch persisted runtime status: %w", err)
	}
	if jsonOutput {
		_, err = output.Write(append(raw, '\n'))
		return err
	}
	lease := "none"
	if status.LeaseExpiresAt != nil {
		lease = status.LeaseExpiresAt.Format(time.RFC3339)
	}
	continuation := "clear"
	if status.ContinuationBlocked {
		if status.UnresolvedActions > 0 {
			continuation = fmt.Sprintf("blocked (%d unresolved consequential action(s))", status.UnresolvedActions)
		} else {
			continuation = "blocked by execution state " + status.ExecutionState
		}
	}
	_, err = fmt.Fprintf(output, "null.select runtime\nExecution: %s (%s)\nRuntime: %s\nModel: %s/%s\nAuthority: %s\nFencing epoch: local %d / canonical %d\nLease expires: %s\nCredential expires: %s\nContinuation: %s\nReady for consequential work: %s\n",
		status.ExecutionID, status.ExecutionState, config.IncarnationID, config.Provider, config.Model,
		status.Authority, config.FencingEpoch, status.CanonicalFencingEpoch, lease,
		status.CredentialExpiresAt.Format(time.RFC3339), continuation, yesNo(status.ReadyForConsequentialWork))
	return err
}

func runDoctorContext(ctx context.Context, args []string, output io.Writer) error {
	configPath, jsonOutput, err := diagnosticFlags("doctor", args, output)
	if err != nil {
		return err
	}
	config, err := loadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("credential file check failed: %w", err)
	}
	status, _, err := fetchWorkloadStatus(ctx, config)
	if err != nil {
		return fmt.Errorf("control plane check failed: %w", err)
	}
	report := doctorReport{
		Healthy: true, ReadyForConsequentialWork: status.ReadyForConsequentialWork, Status: status,
		Checks: []doctorCheck{
			{Name: "credential_file", State: "ok", Message: "credential file is bounded, private, complete, and unexpired"},
			{Name: "control_plane", State: "ok", Message: "control plane authenticated the workload credential"},
			{Name: "runtime_binding", State: checkState(status.CanonicalIncarnationID == config.IncarnationID), Message: "local runtime identity compared with the canonical current incarnation"},
			{Name: "fencing_epoch", State: checkState(status.Authority != "fenced"), Message: fmt.Sprintf("local epoch %d; canonical epoch %d", config.FencingEpoch, status.CanonicalFencingEpoch)},
			{Name: "effect_authority", State: authorityCheckState(status.Authority), Message: "persisted authority is " + status.Authority},
			{Name: "continuation", State: blockedCheckState(status.ContinuationBlocked), Message: continuationMessage(status)},
		},
	}
	if jsonOutput {
		return json.NewEncoder(output).Encode(report)
	}
	_, err = fmt.Fprintln(output, "null.select doctor")
	if err != nil {
		return err
	}
	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(output, "[%s] %s — %s\n", strings.ToUpper(check.State), check.Name, check.Message); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(output, "Ready for consequential work: %s\n", yesNo(report.ReadyForConsequentialWork))
	return err
}

func diagnosticFlags(name string, args []string, output io.Writer) (string, bool, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(output)
	configPath := flags.String("config", defaultClientConfigPath(), "credential configuration path")
	jsonOutput := flags.Bool("json", false, "print machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return "", false, err
	}
	if flags.NArg() != 0 {
		return "", false, fmt.Errorf("%s accepts flags only", name)
	}
	return *configPath, *jsonOutput, nil
}

func fetchWorkloadStatus(ctx context.Context, config clientConfig) (workloadStatusResponse, []byte, error) {
	body, _ := json.Marshal(map[string]any{"incarnation_id": config.IncarnationID, "fencing_epoch": config.FencingEpoch})
	var status workloadStatusResponse
	raw, err := connectRequest(ctx, http.MethodPost, config.Server+"/v1/status", config.CredentialToken, body, &status)
	if err != nil {
		return workloadStatusResponse{}, nil, err
	}
	if err := validateWorkloadStatus(config, status); err != nil {
		return workloadStatusResponse{}, nil, err
	}
	return status, raw, nil
}

func validateWorkloadStatus(config clientConfig, status workloadStatusResponse) error {
	if status.ExecutionID != config.ExecutionID || status.IncarnationID != config.IncarnationID || status.FencingEpoch != config.FencingEpoch || status.CanonicalFencingEpoch < 1 || status.CredentialExpiresAt.IsZero() || status.UnresolvedActions < 0 {
		return errors.New("gateway status response is incomplete or does not match the local runtime")
	}
	if status.Authority != "active" && status.Authority != "frozen" && status.Authority != "fenced" && status.Authority != "expired" {
		return errors.New("gateway status response contains an unknown authority state")
	}
	if status.ReadyForConsequentialWork && (status.Authority != "active" || status.ContinuationBlocked) {
		return errors.New("gateway status response contains contradictory authority state")
	}
	if status.Authority == "active" && status.LeaseExpiresAt == nil {
		return errors.New("gateway status response omitted the active lease expiry")
	}
	return nil
}

func checkState(ok bool) string {
	if ok {
		return "ok"
	}
	return "hold"
}

func authorityCheckState(authority string) string {
	if authority == "active" {
		return "ok"
	}
	return "hold"
}

func blockedCheckState(blocked bool) string {
	if blocked {
		return "hold"
	}
	return "ok"
}

func continuationMessage(status workloadStatusResponse) string {
	if status.UnresolvedActions > 0 {
		return fmt.Sprintf("%d unresolved consequential action(s)", status.UnresolvedActions)
	}
	if status.ContinuationBlocked {
		return "execution state " + status.ExecutionState + " blocks continuation"
	}
	return "no unresolved consequential actions"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
