package analyzer

import (
	"fmt"
	"os"

	"github.com/dockerguard/dockerguard/internal/dockerfile"
	"github.com/dockerguard/dockerguard/internal/rules"
	"github.com/dockerguard/dockerguard/internal/registry"
	"github.com/dockerguard/dockerguard/internal/secrets"
	"github.com/dockerguard/dockerguard/internal/types"
)

// Analyzer performs static analysis on Dockerfiles
type Analyzer struct {
	verbose    bool
	ruleEngine *rules.Engine
	registry   *registry.Client
	secretScan *secrets.Scanner
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(verbose bool) *Analyzer {
	return &Analyzer{
		verbose:    verbose,
		ruleEngine: rules.NewEngine(),
		registry:   registry.NewClient(),
		secretScan: secrets.NewScanner(),
	}
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
		vulnResults, err := a.registry.CheckBaseImage(df.BaseImage)
		if err != nil && a.verbose {
			fmt.Printf("Warning: Could not check base image %s: %v\n", df.BaseImage, err)
		}
		results = append(results, vulnResults...)
	}

	return results, nil
}

