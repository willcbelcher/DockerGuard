package dockerfile

import (
	"bufio"
	"strings"
)

// Dockerfile represents a parsed Dockerfile
type Dockerfile struct {
	BaseImage string
	Instructions []Instruction
}

// Instruction represents a single Dockerfile instruction
type Instruction struct {
	Type    string // RUN, COPY, ENV, etc.
	Args    string
	Line    int
	Raw     string
}

// Parse parses a Dockerfile from raw bytes
func Parse(data []byte) (*Dockerfile, error) {
	df := &Dockerfile{
		Instructions: []Instruction{},
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse instruction
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		instructionType := strings.ToUpper(parts[0])
		args := strings.Join(parts[1:], " ")

		inst := Instruction{
			Type: instructionType,
			Args: args,
			Line: lineNum,
			Raw:  line,
		}

		df.Instructions = append(df.Instructions, inst)

		// Extract base image from FROM instruction
		if instructionType == "FROM" {
			// Handle "FROM image:tag" or "FROM image AS alias"
			imageParts := strings.Fields(args)
			if len(imageParts) > 0 {
				df.BaseImage = imageParts[0]
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return df, nil
}

