package rules

import (
	"regexp"
	"strings"

	"dockerguard/internal/dockerfile"
	"dockerguard/internal/types"
)

// Helper functions for rule creation

// findInstructions finds all instructions of a given type
func findInstructions(df *dockerfile.Dockerfile, instructionType string) []dockerfile.Instruction {
	var found []dockerfile.Instruction
	for _, inst := range df.Instructions {
		if inst.Type == instructionType {
			found = append(found, inst)
		}
	}
	return found
}

// hasInstruction checks if an instruction type exists
func hasInstruction(df *dockerfile.Dockerfile, instructionType string) bool {
	for _, inst := range df.Instructions {
		if inst.Type == instructionType {
			return true
		}
	}
	return false
}

// getEffectiveUser returns the user that will run the container
func getEffectiveUser(df *dockerfile.Dockerfile) (string, int, string) {
	effectiveUser := "root"
	lastUserLine := 0
	lastUserContext := ""

	for _, inst := range df.Instructions {
		if inst.Type == "USER" {
			effectiveUser = inst.Args
			lastUserLine = inst.Line
			lastUserContext = inst.Raw
		}
	}

	return effectiveUser, lastUserLine, lastUserContext
}

// isRootUser checks if a user string represents root
func isRootUser(user string) bool {
	user = strings.TrimSpace(user)
	return user == "root" || user == "0" || strings.HasPrefix(user, "root:")
}

// containsPattern checks if text matches any of the regex patterns
func containsPattern(text string, patterns []*regexp.Regexp) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// createResult is a helper to create a Result with consistent formatting
func createResult(ruleID, severity, message string, line int, context string) types.Result {
	return types.Result{
		Severity: severity,
		RuleID:   ruleID,
		Message:  message,
		Line:     line,
		Context:  context,
	}
}

// checkRunInstruction checks RUN instructions for security issues
func checkRunInstruction(inst dockerfile.Instruction) []types.Result {
	var results []types.Result
	args := strings.ToLower(inst.Args)

	// Check for privilege escalation
	privilegeEscalationPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\bsudo\s+`),
		regexp.MustCompile(`\bsu\s+`),
		regexp.MustCompile(`\bsu\s+-\s*`),
	}

	if containsPattern(args, privilegeEscalationPatterns) {
		results = append(results, createResult(
			"DG004",
			"high",
			"RUN instruction contains privilege escalation (sudo/su)",
			inst.Line,
			inst.Raw,
		))
	}

	// Check for insecure package manager usage
	if strings.Contains(args, "apt-get install") && !strings.Contains(args, "--no-install-recommends") {
		results = append(results, createResult(
			"DG005",
			"medium",
			"apt-get install without --no-install-recommends (increases image size and attack surface)",
			inst.Line,
			inst.Raw,
		))
	}

	// Check for apt-get without update
	if strings.Contains(args, "apt-get install") && !strings.Contains(args, "apt-get update") {
		// Check if update was done in a previous RUN
		results = append(results, createResult(
			"DG006",
			"low",
			"apt-get install should be preceded by apt-get update in the same RUN instruction",
			inst.Line,
			inst.Raw,
		))
	}

	// Check for curl/wget without verification
	if (strings.Contains(args, "curl") || strings.Contains(args, "wget")) &&
		!strings.Contains(args, "sha256sum") &&
		!strings.Contains(args, "gpg") &&
		!strings.Contains(args, "checksum") {
		results = append(results, createResult(
			"DG007",
			"medium",
			"Downloading files with curl/wget without verification (checksum or signature)",
			inst.Line,
			inst.Raw,
		))
	}

	return results
}
