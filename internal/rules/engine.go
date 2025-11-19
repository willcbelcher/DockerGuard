package rules

import (
	"fmt"
	"strings"

	"github.com/dockerguard/dockerguard/internal/dockerfile"
	"github.com/dockerguard/dockerguard/internal/types"
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
		ruleResults := rule.Check(df)
		results = append(results, ruleResults...)
	}

	return results
}

// registerDefaultRules registers built-in security rules
func (e *Engine) registerDefaultRules() {
	// Rule: Check if running as root
	e.rules = append(e.rules, Rule{
		ID:          "DG001",
		Description: "Container should not run as root user",
		Severity:    "high",
		Check: func(df *dockerfile.Dockerfile) []types.Result {
			var results []types.Result
			hasUser := false

			for _, inst := range df.Instructions {
				if inst.Type == "USER" {
					hasUser = true
					// Check if user is root
					if strings.Contains(inst.Args, "root") || inst.Args == "0" {
						results = append(results, types.Result{
							Severity: "high",
							RuleID:   "DG001",
							Message:  "Container runs as root user",
							Line:     inst.Line,
							Context:  inst.Raw,
						})
					}
				}
			}

			if !hasUser {
				results = append(results, types.Result{
					Severity: "high",
					RuleID:   "DG001",
					Message:  "No USER instruction found - container will run as root",
					Line:     0,
					Context:  "",
				})
			}

			return results
		},
	})

	// Rule: Check for exposed secrets in ENV
	e.rules = append(e.rules, Rule{
		ID:          "DG002",
		Description: "Secrets should not be hardcoded in ENV instructions",
		Severity:    "critical",
		Check: func(df *dockerfile.Dockerfile) []types.Result {
			var results []types.Result
			secretKeywords := []string{"password", "secret", "key", "token", "api_key", "apikey"}

			for _, inst := range df.Instructions {
				if inst.Type == "ENV" || inst.Type == "ARG" {
					lowerArgs := strings.ToLower(inst.Args)
					for _, keyword := range secretKeywords {
						if strings.Contains(lowerArgs, keyword) {
							results = append(results, types.Result{
								Severity: "critical",
								RuleID:   "DG002",
								Message:  fmt.Sprintf("Potential secret found in %s instruction", inst.Type),
								Line:     inst.Line,
								Context:  inst.Raw,
							})
						}
					}
				}
			}

			return results
		},
	})

	// Rule: Check for latest tag
	e.rules = append(e.rules, Rule{
		ID:          "DG003",
		Description: "Base image should not use 'latest' tag",
		Severity:    "medium",
		Check: func(df *dockerfile.Dockerfile) []types.Result {
			var results []types.Result

			if strings.HasSuffix(df.BaseImage, ":latest") || !strings.Contains(df.BaseImage, ":") {
				results = append(results, types.Result{
					Severity: "medium",
					RuleID:   "DG003",
					Message:  "Base image uses 'latest' tag or no tag specified",
					Line:     0,
					Context:  df.BaseImage,
				})
			}

			return results
		},
	})
}

