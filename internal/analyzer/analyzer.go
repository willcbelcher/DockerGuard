package analyzer

import (
	"fmt"
	"os"

	"dockerguard/internal/config"
	"dockerguard/internal/dockerfile"
	"dockerguard/internal/registry"
	"dockerguard/internal/rules"
	"dockerguard/internal/secrets"
	"dockerguard/internal/types"
)

// Analyzer performs static analysis on Dockerfiles
type Analyzer struct {
	verbose    bool
	ruleEngine *rules.Engine
	registry   *registry.Client
	secretScan *secrets.Scanner
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(verbose bool, configPath string) (*Analyzer, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	engine := rules.NewEngine()
	engine.ApplyConfig(cfg)

	return &Analyzer{
		verbose:    verbose,
		ruleEngine: engine,
		registry:   registry.NewClient(),
		secretScan: secrets.NewScanner(),
	}, nil
}

// Analyze performs analysis on the given Dockerfile
func (a *Analyzer) Analyze(filePath string) ([]types.Result, error) {
	// Read and parse Dockerfile
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Dockerfile: %w", err)
	}

	df, err := dockerfile.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Dockerfile: %w", err)
	}

	var results []types.Result

	// Run rule-based checks
	ruleResults := a.ruleEngine.Check(df)
	results = append(results, ruleResults...)

	// Check for secrets
	secretResults := a.secretScan.Scan(df)
	results = append(results, secretResults...)

	// Check base image vulnerabilities
	if df.BaseImage != "" {
		baseDf, err := a.registry.CheckBaseImage(df.BaseImage)
		if err != nil {
			fmt.Printf("Warning: Could not check base image %s: %v\n", df.BaseImage, err)
		} else {
			// Recursively analyze the base image
			// Run rule-based checks on base image
			baseRuleResults := a.ruleEngine.Check(baseDf)
			for _, res := range baseRuleResults {
				res.Message = fmt.Sprintf("[Base Image: %s] %s", df.BaseImage, res.Message)
				results = append(results, res)
			}

			// Check for secrets in base image
			baseSecretResults := a.secretScan.Scan(baseDf)
			for _, res := range baseSecretResults {
				res.Message = fmt.Sprintf("[Base Image: %s] %s", df.BaseImage, res.Message)
				results = append(results, res)
			}
		}
	}

	return results, nil
}
