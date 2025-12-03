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
	cmd.Flags().StringP("rules", "r", "", "Path to custom rules file (optional)")
	cmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	return cmd
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	filePath, _ := cmd.Flags().GetString("file")
	verbose, _ := cmd.Flags().GetBool("verbose")

	analyzer := analyzer.NewAnalyzer(verbose)
	results, err := analyzer.Analyze(filePath)
	if err != nil {
		return err
	}

	// Print results
	for _, result := range results {
		fmt.Printf("[%s] %s: %s\n", result.Severity, result.RuleID, result.Message)
		if result.Line > 0 {
			fmt.Printf("  Line %d: %s\n", result.Line, result.Context)
		}
	}

	return nil
}
