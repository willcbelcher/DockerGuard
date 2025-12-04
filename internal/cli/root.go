package cli

import (
	"fmt"

	"dockerguard/internal/analyzer"

	"github.com/spf13/cobra"
)

// NewRootCommand creates and returns the root cobra command
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dockerguard",
		Short: "Static analysis tool for Dockerfile security",
		Long: `DockerGuard is a static vulnerability analysis tool for Dockerfiles.
It analyzes Dockerfiles for security misconfigurations, vulnerabilities,
and leaked secrets before building images.`,
		RunE: runAnalyze,
	}

	cmd.Flags().StringP("file", "f", "Dockerfile", "Path to Dockerfile to analyze")
	cmd.Flags().StringP("config", "c", "", "Path to configuration file (optional)")
	cmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	return cmd
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	filePath, _ := cmd.Flags().GetString("file")
	configPath, _ := cmd.Flags().GetString("config")
	verbose, _ := cmd.Flags().GetBool("verbose")

	analyzer, err := analyzer.NewAnalyzer(verbose, configPath)
	if err != nil {
		return err
	}
	results, err := analyzer.Analyze(filePath)
	if err != nil {
		return err
	}

	// Print results
	for _, result := range results {
		// Skip low severity if not verbose
		if !verbose && result.Severity == "low" {
			continue
		}

		fmt.Printf("[%s] %s: %s\n", result.Severity, result.RuleID, result.Message)
		if result.Line > 0 {
			fmt.Printf("  Line %d: %s\n", result.Line, result.Context)
		}
	}

	return nil
}
