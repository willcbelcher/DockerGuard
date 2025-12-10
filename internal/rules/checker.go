package rules

import (
	"fmt"
	"regexp"
	"strings"

	"dockerguard/internal/config"
	"dockerguard/internal/dockerfile"
	"dockerguard/internal/types"
)

type secretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}

var secretPatterns = []secretPattern{
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "critical",
	},
	{
		Name:     "API Key",
		Pattern:  regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?[a-zA-Z0-9]{20,}['"]?`),
		Severity: "critical",
	},
	{
		Name:     "Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE KEY-----`),
		Severity: "critical",
	},
	{
		Name:     "Password",
		Pattern:  regexp.MustCompile(`(?i)(password|pwd|passwd)\s*[=:]\s*['"]?[^'\s"]+['"]?`),
		Severity: "high",
	},
}

// RuleChecker manages and executes security rules
type RuleChecker struct {
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

// NewRuleChecker creates a new rule checker with default rules
func NewRuleChecker() *RuleChecker {
	checker := &RuleChecker{
		rules: []Rule{},
	}

	// Register default rules
	checker.registerDefaultRules()

	return checker
}

// Check runs all rules against the Dockerfile
func (e *RuleChecker) Check(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, rule := range e.rules {
		if rule.Disabled {
			continue
		}
		ruleResults := rule.Check(df)
		// Override severity only when a rule-level severity is set (supports per-result severity like SECRET patterns)
		if rule.Severity != "" {
			for i := range ruleResults {
				ruleResults[i].Severity = rule.Severity
			}
		}
		results = append(results, ruleResults...)
	}

	return results
}

// registerDefaultRules registers built-in security rules
func (e *RuleChecker) registerDefaultRules() {
	// Rule ROOT_USER: Check if running as root
	e.registerRule("ROOT_USER", "Container should not run as root user", "high", e.checkRootUser)

	// Rule BASE_IMAGE_LATEST: Check for latest tag
	e.registerRule("BASE_IMAGE_LATEST", "Base image should not use 'latest' tag", "medium", e.checkLatestTag)

	// Rule RUN_PRIV_ESC: Check for privilege escalation in RUN
	e.registerRule("RUN_PRIV_ESC", "RUN instructions should not contain privilege escalation", "high", e.checkPrivilegeEscalation)

	// Rule PKG_MGR_BEST_PRACTICE: Check for insecure package manager usage
	e.registerRule("PKG_MGR_BEST_PRACTICE", "Package managers should use security best practices", "medium", e.checkPackageManager)

	// Rule APT_INSTALL_NO_UPDATE: Check apt-get update usage
	e.registerRule("APT_INSTALL_NO_UPDATE", "apt-get install should be combined with apt-get update", "low", e.checkAptGetUpdate)

	// Rule UNVERIFIED_DOWNLOAD: Check for unverified downloads
	// e.registerRule("UNVERIFIED_DOWNLOAD", "Downloads should be verified with checksums or signatures", "medium", e.checkUnverifiedDownloads)

	// Rule ADD_INSTEAD_OF_COPY: Check for ADD vs COPY
	e.registerRule("ADD_INSTEAD_OF_COPY", "Use COPY instead of ADD unless you need ADD's special features", "medium", e.checkAddVsCopy)

	// Rule EXPOSE_DOCUMENTATION: Check for exposed ports
	e.registerRule("EXPOSE_DOCUMENTATION", "EXPOSE should be documented and necessary", "low", e.checkExposedPorts) // TODO: rename to EXPOSED_PORTS

	// Rule MISSING_HEALTHCHECK: Check for healthcheck
	e.registerRule("MISSING_HEALTHCHECK", "Consider adding HEALTHCHECK instruction", "low", e.checkHealthcheck)

	// Rule WORKDIR_ROOT: Check for WORKDIR in root
	e.registerRule("WORKDIR_ROOT", "WORKDIR should not be set to root directory", "medium", e.checkWorkdirRoot)

	// Rule CURL_BASHING: Detect piping curl/wget output into a shell
	e.registerRule("CURL_BASHING", "Avoid piping curl/wget output directly into a shell; verify downloads first", "high", e.checkCurlBash)

	// Rule SECRET: Check for exposed secrets (pattern-based and keyword-based in ENV/ARG)
	e.registerRule("SECRET", "Secrets should not be hardcoded anywhere in the Dockerfile", "", e.checkSecrets)
}

// registerRule is a helper to register rules
func (e *RuleChecker) registerRule(id, description, severity string, checkFunc func(*dockerfile.Dockerfile) []types.Result) {
	e.rules = append(e.rules, Rule{
		ID:          id,
		Description: description,
		Severity:    severity,
		Check:       checkFunc,
	})
}

func (e *RuleChecker) checkRootUser(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result
	effectiveUser, lastUserLine, lastUserContext := getEffectiveUser(df)

	if isRootUser(effectiveUser) {
		message := "Container runs as root user"
		if lastUserLine == 0 {
			message = "No USER instruction found - container will run as root"
		}

		results = append(results, createResult(
			"ROOT_USER",
			"high",
			message,
			lastUserLine,
			lastUserContext,
		))
	}

	return results
}


func (e *RuleChecker) checkLatestTag(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	if df.BaseImage == "" {
		return results
	}

	if strings.HasSuffix(df.BaseImage, ":latest") || (!strings.Contains(df.BaseImage, ":") && !strings.Contains(df.BaseImage, "@")) {
		results = append(results, createResult(
			"BASE_IMAGE_LATEST",
			"medium",
			"Base image uses 'latest' tag or no tag specified (use specific version tags for reproducibility)",
			0,
			df.BaseImage,
		))
	}

	return results
}

// checks RUN instructions for privilege escalation
func (e *RuleChecker) checkPrivilegeEscalation(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for privilege escalation only
			for _, r := range runResults {
				if r.RuleID == "RUN_PRIV_ESC" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// check for insecure package manager usage
func (e *RuleChecker) checkPackageManager(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for package manager issues only
			for _, r := range runResults {
				if r.RuleID == "PKG_MGR_BEST_PRACTICE" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// checkAptGetUpdate checks if apt-get install is properly combined with update
func (e *RuleChecker) checkAptGetUpdate(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "RUN" {
			runResults := checkRunInstruction(inst)
			// Filter for apt-get update issues only
			for _, r := range runResults {
				if r.RuleID == "APT_INSTALL_NO_UPDATE" {
					results = append(results, r)
				}
			}
		}
	}

	return results
}

// checkUnverifiedDownloads checks for unverified downloads
// func (e *RuleChecker) checkUnverifiedDownloads(df *dockerfile.Dockerfile) []types.Result {
// 	var results []types.Result

// 	for _, inst := range df.Instructions {
// 		if inst.Type == "RUN" {
// 			runResults := checkRunInstruction(inst)
// 			// Filter for download verification issues only
// 			for _, r := range runResults {
// 				if r.RuleID == "UNVERIFIED_DOWNLOAD" {
// 					results = append(results, r)
// 				}
// 			}
// 		}
// 	}

// 	return results
// }

// checkAddVsCopy checks for ADD usage (should prefer COPY)
func (e *RuleChecker) checkAddVsCopy(df *dockerfile.Dockerfile) []types.Result {
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
					"ADD_INSTEAD_OF_COPY",
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

func (e *RuleChecker) checkExposedPorts(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	exposedPorts := findInstructions(df, "EXPOSE")
	if len(exposedPorts) == 0 {
		// This is informational, not necessarily a security issue
		return results
	}

	return results
}

func (e *RuleChecker) checkHealthcheck(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	if !hasInstruction(df, "HEALTHCHECK") {
		results = append(results, createResult(
			"MISSING_HEALTHCHECK",
			"low",
			"Consider adding HEALTHCHECK instruction for better container orchestration",
			0,
			"",
		))
	}

	return results
}

func (e *RuleChecker) checkWorkdirRoot(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type == "WORKDIR" {
			workdir := strings.TrimSpace(inst.Args)
			if workdir == "/" || workdir == "/root" {
				results = append(results, createResult(
					"WORKDIR_ROOT",
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

var curlBashRegex = regexp.MustCompile(`(?i)(curl|wget)[^|>]*[|>]`)

// detect piping curl/wget output directly into a shell
func (e *RuleChecker) checkCurlBash(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		if inst.Type != "RUN" {
			continue
		}

		if curlBashRegex.MatchString(inst.Raw) {
			results = append(results, createResult(
				"CURL_BASHING",
				"high",
				"Avoid curl/wget piping into a shell, use trusted sources and verify integrity",
				inst.Line,
				inst.Raw,
			))
		}
	}

	return results
}

func (e *RuleChecker) checkSecrets(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result
	secretKeywords := []string{"password", "secret", "key", "token", "api_key", "apikey", "credential", "auth"}

	for _, inst := range df.Instructions {
		// Check for pattern-based secrets (regex patterns) in all instructions
		for _, pattern := range secretPatterns {
			if pattern.Pattern.MatchString(inst.Raw) {
				// Use pattern severity unless overridden by config in Check()
				results = append(results, types.Result{
					Severity: pattern.Severity,
					RuleID:   "SECRET",
					Message:  fmt.Sprintf("Potential %s detected", pattern.Name),
					Line:     inst.Line,
					Context:  inst.Raw,
				})
			}
		}

		// Check for keyword-based secrets in ENV/ARG instructions
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
						"SECRET",
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

// applies configuration to the rules
func (e *RuleChecker) ApplyConfig(cfg *config.Config) {
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
