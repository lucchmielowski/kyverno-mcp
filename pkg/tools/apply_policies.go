// Package tools provides tools for the MCP server.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	kyverno "github.com/nirmata/kyverno-mcp/pkg/kyverno-cli"

	"github.com/kyverno/kyverno/cmd/cli/kubectl-kyverno/commands/apply"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"k8s.io/klog/v2"

	_ "embed"
)

//go:embed policies/pod-security.yaml
var podSecurityPolicy []byte

//go:embed policies/rbac-best-practices.yaml
var rbacBestPracticesPolicy []byte

//go:embed policies/kubernetes-best-practices.yaml
var kubernetesBestPracticesPolicy []byte

func defaultPolicies() []byte {
	combinedPolicy := strings.TrimSpace(string(podSecurityPolicy)) + "\n---\n" + strings.TrimSpace(string(rbacBestPracticesPolicy)) + "\n---\n" + strings.TrimSpace(string(kubernetesBestPracticesPolicy))
	return []byte(combinedPolicy)
}

// cleanupFile removes the specified file from disk.
func cleanupFile(name string) {
	_ = os.Remove(name)
}

func applyPolicy(payload string) (string, error) {
	// Select the appropriate embedded policy content based on the requested key
	policyData := defaultPolicies()

	// Create a resource file from the payload
	tmpResourceFile, err := os.CreateTemp("", "kyverno-resource-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp resource file: %w", err)
	}
	defer cleanupFile(tmpResourceFile.Name())

	if _, err := tmpResourceFile.WriteString(payload); err != nil {
		if cerr := tmpResourceFile.Close(); cerr != nil {
			klog.ErrorS(cerr, "failed to close resource temp file after write error")
		}
		return "", fmt.Errorf("failed to write resource payload to temp file: %w", err)
	}

	// Create a uniquely named temporary file to avoid collisions between concurrent requests.
	tmpFile, err := os.CreateTemp("", "kyverno-policy-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp policy file: %w", err)
	}

	// Ensure the file is cleaned up after we have finished processing.
	// The cleanup is deferred *after* the temp file is successfully created so that
	// the file is always removed regardless of subsequent failures.
	defer cleanupFile(tmpFile.Name())

	// Write the selected policy content to the temporary file
	if _, err := tmpFile.Write(policyData); err != nil {
		if cerr := tmpFile.Close(); cerr != nil {
			klog.ErrorS(cerr, "failed to close temp file after write error")
		}
		return "", fmt.Errorf("failed to write policy data to temp file: %w", err)
	}

	// Flush the file to disk before it's used by downstream helpers
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("failed to close temp policy file: %w", err)
	}

	applyCommandConfig := &apply.ApplyCommandConfig{
		PolicyPaths:   []string{tmpFile.Name()},
		ResourcePaths: []string{tmpResourceFile.Name()},
		PolicyReport:  true,
		OutputFormat:  "json",
		GitBranch:     "main",
	}

	result, err := kyverno.ApplyCommandHelper(applyCommandConfig)
	if err != nil {
		return "", fmt.Errorf("failed to apply policy: %w", err)
	}

	results := kyverno.BuildPolicyReportResults(false, result.EngineResponses...)
	jsonResults, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy report results: %w", err)
	}

	return string(jsonResults), nil
}

func ApplyPolicies(s *server.MCPServer) {
	klog.InfoS("Registering tool: apply_policies")
	applyPoliciesTool := mcp.NewTool(
		"apply_policies",
		mcp.WithDescription(`Validates payloads against Kyverno policy sets. The payloads should contain a list of YAML resources in string format. The resources are validated against the specified policy set, or the default policy sets if none is specified.`),
		mcp.WithString("payloads", mcp.Description(`K8s resources in YAML format to apply policies against.`)),
	)

	s.AddTool(applyPoliciesTool, func(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, ok := request.Params.Arguments.(map[string]any)
		if !ok {
			return mcp.NewToolResultError("Error: invalid arguments format"), nil
		}

		payloads := ""
		if args["payloads"] != nil {
			payloads = args["payloads"].(string)
		}

		results, err := applyPolicy(payloads)
		if err != nil {
			// Surface the error back to the MCP client without terminating the server.
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(results), nil
	})
}
