package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const githubCapabilityDigest = "85296a14414ff03254cddea0c0d198c3b4a46f1de8cc6b2296ebb058bdc80216"

var (
	githubOwnerPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	clientSafeID            = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

type githubResult struct {
	ActionID               string `json:"action_id"`
	AttemptID              string `json:"attempt_id"`
	Outcome                string `json:"outcome"`
	AttemptState           string `json:"attempt_state"`
	Finding                string `json:"finding"`
	RequiresReconciliation bool   `json:"requires_reconciliation"`
}

func runGitHubContext(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprintln(output, githubUsage())
		return err
	}
	switch args[0] {
	case "label":
		return runGitHubLabel(ctx, args[1:], output)
	case "observe":
		return runGitHubObserve(ctx, args[1:], output)
	default:
		return fmt.Errorf("unknown github command %q\n\n%s", args[0], githubUsage())
	}
}

func runGitHubLabel(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("github label", flag.ContinueOnError)
	flags.SetOutput(output)
	owner := flags.String("owner", "", "GitHub repository owner")
	repository := flags.String("repo", "", "GitHub repository name")
	pullRequest := flags.Int64("pr", 0, "pull request number")
	label := flags.String("label", "", "label to add")
	configPath := flags.String("config", defaultClientConfigPath(), "credential configuration path")
	idempotencyKey := flags.String("idempotency-key", "", "stable request key used for safe replay")
	jsonOutput := flags.Bool("json", false, "print machine-readable result")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !githubOwnerPattern.MatchString(*owner) || !githubRepositoryPattern.MatchString(*repository) || *pullRequest < 1 || !validClientLabel(*label) {
		return errors.New("--owner, --repo, positive --pr, and a 1-50 character --label are required")
	}
	config, err := loadGitHubConfig(*configPath)
	if err != nil {
		return err
	}
	if !clientSafeID.MatchString(*idempotencyKey) {
		return errors.New("--idempotency-key is required and must be 1-128 letters, numbers, dots, colons, underscores, or hyphens")
	}
	body, _ := json.Marshal(map[string]any{
		"incarnation_id": config.IncarnationID, "fencing_epoch": config.FencingEpoch, "owner": *owner, "repository": *repository,
		"pull_request": *pullRequest, "label": *label, "idempotency_key": *idempotencyKey, "correlation_id": "null-cli-" + *idempotencyKey,
	})
	var result githubResult
	_, err = connectRequest(ctx, http.MethodPost, config.Server+"/v1/executions/"+url.PathEscape(config.ExecutionID)+"/github/pull-request-labels", config.CredentialToken, body, &result)
	if err != nil {
		return fmt.Errorf("protect GitHub label action (retry with --idempotency-key %s): %w", *idempotencyKey, err)
	}
	if result.ActionID == "" || result.AttemptID == "" || result.AttemptState == "" {
		return errors.New("GitHub adapter response was incomplete")
	}
	if *jsonOutput {
		return json.NewEncoder(output).Encode(result)
	}
	_, err = fmt.Fprintf(output, "GitHub action recorded\nAction: %s\nAttempt: %s\nState: %s\n", result.ActionID, result.AttemptID, result.AttemptState)
	if err == nil && result.Finding != "" {
		_, err = fmt.Fprintf(output, "Authoritative finding: %s\n", result.Finding)
	}
	if err == nil && result.RequiresReconciliation {
		_, err = fmt.Fprintf(output, "Continuation hold: active\nReconcile with: null github observe --attempt %s\n", result.AttemptID)
	}
	return err
}

func runGitHubObserve(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("github observe", flag.ContinueOnError)
	flags.SetOutput(output)
	attemptID := flags.String("attempt", "", "action attempt identifier")
	configPath := flags.String("config", defaultClientConfigPath(), "credential configuration path")
	jsonOutput := flags.Bool("json", false, "print machine-readable result")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !clientSafeID.MatchString(*attemptID) {
		return errors.New("--attempt is required")
	}
	config, err := loadGitHubConfig(*configPath)
	if err != nil {
		return err
	}
	var result githubResult
	_, err = connectRequest(ctx, http.MethodPost, config.Server+"/v1/github/attempts/"+url.PathEscape(*attemptID)+"/observe", config.CredentialToken, []byte(`{}`), &result)
	if err != nil {
		return fmt.Errorf("observe GitHub action: %w", err)
	}
	if result.AttemptID == "" || result.AttemptState == "" {
		return errors.New("GitHub verifier response was incomplete")
	}
	if *jsonOutput {
		return json.NewEncoder(output).Encode(result)
	}
	_, err = fmt.Fprintf(output, "GitHub attempt observed\nAttempt: %s\nState: %s\nFinding: %s\n", result.AttemptID, result.AttemptState, result.Finding)
	return err
}

func loadGitHubConfig(path string) (clientConfig, error) {
	config, err := loadClientConfig(path)
	if err != nil {
		return clientConfig{}, fmt.Errorf("load connected runtime: %w", err)
	}
	if time.Now().After(config.ExpiresAt) {
		return clientConfig{}, errors.New("workload credential has expired; create a new console enrollment")
	}
	if config.FencingEpoch < 1 {
		return clientConfig{}, errors.New("saved runtime predates effect commands; run the same null connect command once to record its fencing epoch")
	}
	if config.CapabilityDigest != githubCapabilityDigest {
		return clientConfig{}, fmt.Errorf("runtime capability does not admit GitHub labels; reconnect with --capability-digest %s", githubCapabilityDigest)
	}
	return config, nil
}

func validClientLabel(value string) bool {
	if strings.TrimSpace(value) != value || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 50 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func githubUsage() string {
	return "usage:\n  null github label --owner OWNER --repo REPO --pr NUMBER --label LABEL --idempotency-key KEY\n  null github observe --attempt ATTEMPT_ID"
}
