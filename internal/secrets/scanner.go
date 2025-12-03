package secrets

import (
	"fmt"
	"regexp"

	"dockerguard/internal/dockerfile"
	"dockerguard/internal/types"
)

// Scanner detects secrets and sensitive information in Dockerfiles
type Scanner struct {
	patterns []SecretPattern
}

// SecretPattern defines a pattern to detect secrets
type SecretPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
}

// NewScanner creates a new secret scanner
func NewScanner() *Scanner {
	scanner := &Scanner{
		patterns: []SecretPattern{},
	}

	scanner.registerPatterns()

	return scanner
}

// Scan scans the Dockerfile for secrets
func (s *Scanner) Scan(df *dockerfile.Dockerfile) []types.Result {
	var results []types.Result

	for _, inst := range df.Instructions {
		for _, pattern := range s.patterns {
			if pattern.Pattern.MatchString(inst.Raw) {
				results = append(results, types.Result{
					Severity: pattern.Severity,
					RuleID:   "SECRET",
					Message:  fmt.Sprintf("Potential %s detected", pattern.Name),
					Line:     inst.Line,
					Context:  inst.Raw,
				})
			}
		}
	}

	return results
}

// registerPatterns registers common secret patterns
func (s *Scanner) registerPatterns() {
	// AWS Access Key
	s.patterns = append(s.patterns, SecretPattern{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "critical",
	})

	// Generic API key pattern
	s.patterns = append(s.patterns, SecretPattern{
		Name:     "API Key",
		Pattern:  regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?[a-zA-Z0-9]{20,}['"]?`),
		Severity: "critical",
	})

	// Private key pattern
	s.patterns = append(s.patterns, SecretPattern{
		Name:     "Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE KEY-----`),
		Severity: "critical",
	})

	// Password pattern
	s.patterns = append(s.patterns, SecretPattern{
		Name:     "Password",
		Pattern:  regexp.MustCompile(`(?i)(password|pwd|passwd)\s*[=:]\s*['"]?[^'\s"]+['"]?`),
		Severity: "high",
	})
}
