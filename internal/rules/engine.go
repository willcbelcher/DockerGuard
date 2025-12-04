package rules

import (
	"fmt"
	"strings"

	"dockerguard/internal/config"
	"dockerguard/internal/dockerfile"
	"dockerguard/internal/types"
)

// Engine manages and executes security rules
type Engine struct {
	rules []Rule
}

// Rule defines a security check
type Rule struct {
	ID          string
	Description string
	Severity    string
	Disabled    bool
	Check       func(*dockerfile.Dockerfile) []types.Result
}

// NewEngine creates a new rule engine with default rules
func NewEngine() *Engine {
	engine := &Engine{
		rules: []Rule{},
	}

	// Register default rules
	engine.registerDefaultRules()

	return engine
}

// Check runs all rules against the Dockerfile
func (e *Engine) Check(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, rule := range e.rules {
		if rule.Disabled {
			continue
		}
		ruleResults := rule.Check(df)
		// Update severity if needed (though we updated the rule struct itself, the result creation uses hardcoded severity strings in check functions)
		// So we need to override the severity in the results
		for i := range ruleResults {
			ruleResults[i].Severity = rule.Severity
		}
		results = append(results, ruleResults...)
	}

	return results
}

// registerDefaultRules registers built-in security rules
func (e *Engine) registerDefaultRules() {
	// Rule DG001: Check if running as root
	e.registerRule("DG001", "Container should not run as root user", "high", e.checkRootUser)

	// Rule DG002: Check for exposed secrets in ENV
	e.registerRule("DG002", "Secrets should not be hardcoded in ENV instructions", "critical", e.checkHardcodedSecrets)

	// Rule DG003: Check for latest tag
	e.registerRule("DG003", "Base image should not use 'latest' tag", "medium", e.checkLatestTag)

	// Rule DG004: Check for privilege escalation in RUN
	e.registerRule("DG004", "RUN instructions should not contain privilege escalation", "high", e.checkPrivilegeEscalation)

	// Rule DG005: Check for insecure package manager usage
	e.registerRule("DG005", "Package managers should use security best practices", "medium", e.checkPackageManager)

	// Rule DG006: Check apt-get update usage
	e.registerRule("DG006", "apt-get install should be combined with apt-get update", "low", e.checkAptGetUpdate)

	// Rule DG007: Check for unverified downloads
	e.registerRule("DG007", "Downloads should be verified with checksums or signatures", "medium", e.checkUnverifiedDownloads)

	// Rule DG008: Check for ADD vs COPY
	e.registerRule("DG008", "Use COPY instead of ADD unless you need ADD's special features", "medium", e.checkAddVsCopy)

	// Rule DG009: Check for exposed ports
	e.registerRule("DG009", "EXPOSE should be documented and necessary", "low", e.checkExposedPorts)

	// Rule DG010: Check for healthcheck
	e.registerRule("DG010", "Consider adding HEALTHCHECK instruction", "low", e.checkHealthcheck)

	// Rule DG011: Check for WORKDIR in root
	e.registerRule("DG011", "WORKDIR should not be set to root directory", "medium", e.checkWorkdirRoot)

	// Rule DG012: Check for CMD/ENTRYPOINT security
	e.registerRule("DG012", "CMD/ENTRYPOINT should use exec form for better signal handling", "low", e.checkCmdForm)
}

// registerRule is a helper to register rules
func (e *Engine) registerRule(id, description, severity string, checkFunc func(*dockerfile.Dockerfile) []types.Result) {
	e.rules = append(e.rules, Rule{
		ID:          id,
		Description: description,
		Severity:    severity,
		Check:       checkFunc,
	})
}

// checkRootUser checks if container runs as root
func (e *Engine) checkRootUser(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result
	effectiveUser, lastUserLine, lastUserContext := getEffectiveUser(df)

	if isRootUser(effectiveUser) {
		message := "Container runs as root user"
		if lastUserLine == 0 {
			message = "No USER instruction found - container will run as root"
		}

		results = append(results, createResult(
			"DG001",
			"high",
			message,
			lastUserLine,
			lastUserContext,
		))
	}

	return results
}

// checkHardcodedSecrets checks for secrets in ENV/ARG instructions
func (e *Engine) checkHardcodedSecrets(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result
	secretKeywords := []string{"password", "secret", "key", "token", "api_key", "apikey", "credential", "auth"}

	for _, inst := range df.Instructions {
		if inst.Type == "ENV" || inst.Type == "ARG" {
			// Skip if it looks like a variable reference (e.g. $VAR or ${VAR})
			if strings.Contains(inst.Args, "$") {
				continue
			}

			// Skip ARG declarations without default value (e.g. ARG API_KEY)
			if inst.Type == "ARG" && !strings.Contains(inst.Args, "=") {
				continue
			}

			lowerArgs := strings.ToLower(inst.Args)
			for _, keyword := range secretKeywords {
				if strings.Contains(lowerArgs, keyword) {
					results = append(results, createResult(
						"DG002",
						"critical",
						fmt.Sprintf("Potential secret found in %s instruction", inst.Type),
						inst.Line,
						inst.Raw,
					))
					break // Avoid duplicate results for same instruction
				}
			}
		}
	}

	return results
}

// checkLatestTag checks if base image uses latest tag
func (e *Engine) checkLatestTag(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	if df.BaseImage == "" {
		return results
	}

	if strings.HasSuffix(df.BaseImage, ":latest") || (!strings.Contains(df.BaseImage, ":") && !strings.Contains(df.BaseImage, "@")) {
		results = append(results, createResult(
			"DG003",
			"medium",
			"Base image uses 'latest' tag or no tag specified (use specific version tags for reproducibility)",
			0,
			df.BaseImage,
		))
	}

	return results
}

// checkPrivilegeEscalation checks RUN instructions for privilege escalation
func (e *Engine) checkPrivilegeEscalation(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for privilege escalation only
			for _, r := range runResults {
				if r.RuleID == "DG004" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// checkPackageManager checks for insecure package manager usage
func (e *Engine) checkPackageManager(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for package manager issues only
			for _, r := range runResults {
				if r.RuleID == "DG005" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// checkAptGetUpdate checks if apt-get install is properly combined with update
func (e *Engine) checkAptGetUpdate(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for apt-get update issues only
			for _, r := range runResults {
				if r.RuleID == "DG006" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// checkUnverifiedDownloads checks for unverified downloads
func (e *Engine) checkUnverifiedDownloads(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for download verification issues only
			for _, r := range runResults {
				if r.RuleID == "DG007" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// checkAddVsCopy checks for ADD usage (should prefer COPY)
func (e *Engine) checkAddVsCopy(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "ADD" {
			// ADD is acceptable for URLs or tar extraction, but COPY is preferred for local files
			args := inst.Args
			// Check if it's a URL (starts with http:// or https://)
			isURL := strings.HasPrefix(args, "http://") || strings.HasPrefix(args, "https://")
			// Check if it's extracting a tar file
			isTarExtraction := strings.Contains(args, ".tar") || strings.Contains(args, ".tar.gz") || strings.Contains(args, ".tgz")

			if !isURL && !isTarExtraction {
				results = append(results, createResult(
					"DG008",
					"medium",
					"Use COPY instead of ADD for local files (ADD has additional features that may be unnecessary)",
					inst.Line,
					inst.Raw,
				))
			}
		}
	}

	return results
}

// checkExposedPorts checks for exposed ports
func (e *Engine) checkExposedPorts(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	exposedPorts := findInstructions(df, "EXPOSE")
	if len(exposedPorts) == 0 {
		// This is informational, not necessarily a security issue
		return results
	}

	// Check if ports are documented (this is a best practice check)
	// In a real implementation, you might want to check if ports match CMD/ENTRYPOINT
	return results
}

// checkHealthcheck checks if HEALTHCHECK is present
func (e *Engine) checkHealthcheck(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	if !hasInstruction(df, "HEALTHCHECK") {
		results = append(results, createResult(
			"DG010",
			"low",
			"Consider adding HEALTHCHECK instruction for better container orchestration",
			0,
			"",
		))
	}

	return results
}

// checkWorkdirRoot checks if WORKDIR is set to root
func (e *Engine) checkWorkdirRoot(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "WORKDIR" {
			workdir := strings.TrimSpace(inst.Args)
			if workdir == "/" || workdir == "/root" {
				results = append(results, createResult(
					"DG011",
					"medium",
					"WORKDIR should not be set to root directory (use a non-root directory)",
					inst.Line,
					inst.Raw,
				))
			}
		}
	}

	return results
}

// checkCmdForm checks if CMD/ENTRYPOINT use exec form
func (e *Engine) checkCmdForm(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "CMD" || inst.Type == "ENTRYPOINT" {
			// Exec form uses JSON array: ["cmd", "arg"]
			// Shell form uses string: cmd arg
			args := strings.TrimSpace(inst.Args)
			if !strings.HasPrefix(args, "[") {
				results = append(results, createResult(
					"DG012",
					"low",
					fmt.Sprintf("%s should use exec form (JSON array) for better signal handling", inst.Type),
					inst.Line,
					inst.Raw,
				))
			}
		}
	}

	return results
}

// ApplyConfig applies configuration to the rules
func (e *Engine) ApplyConfig(cfg *config.Config) {
	for i := range e.rules {
		rule := &e.rules[i]
		if ruleConfig, ok := cfg.Rules[rule.ID]; ok {
			if ruleConfig.Disabled {
				rule.Disabled = true
			}
			if ruleConfig.Severity != "" {
				rule.Severity = ruleConfig.Severity
			}
		}
	}
}
