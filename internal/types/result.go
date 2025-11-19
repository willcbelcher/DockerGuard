package types

// Result represents a single analysis result
type Result struct {
	Severity string // "critical", "high", "medium", "low"
	RuleID   string
	Message  string
	Line     int
	Context  string
}

