package dockerfile

import (
	"strings"
)

// HistoryItem represents a layer in the image history
type HistoryItem struct {
	CreatedBy string
}

// FromHistory converts image history to a Dockerfile struct
func FromHistory(history []HistoryItem) *Dockerfile {
	df := &Dockerfile{
		Instructions: []Instruction{},
	}

	for i, item := range history {
		raw := item.CreatedBy
		
		// Clean up the command
		// Docker history often looks like: /bin/sh -c #(nop) CMD ["/bin/bash"]
		// or: /bin/sh -c apt-get update
		
		clean := raw
		clean = strings.Replace(clean, "/bin/sh -c #(nop) ", "", 1)
		clean = strings.Replace(clean, "/bin/sh -c ", "", 1)
		
		// Determine type (heuristic)
		instType := "RUN"
		if strings.HasPrefix(clean, "CMD") {
			instType = "CMD"
		} else if strings.HasPrefix(clean, "ENTRYPOINT") {
			instType = "ENTRYPOINT"
		} else if strings.HasPrefix(clean, "ENV") {
			instType = "ENV"
		} else if strings.HasPrefix(clean, "EXPOSE") {
			instType = "EXPOSE"
		} else if strings.HasPrefix(clean, "WORKDIR") {
			instType = "WORKDIR"
		} else if strings.HasPrefix(clean, "USER") {
			instType = "USER"
		} else if strings.HasPrefix(clean, "ADD") {
			instType = "ADD"
		} else if strings.HasPrefix(clean, "COPY") {
			instType = "COPY"
		} else if strings.HasPrefix(clean, "VOLUME") {
			instType = "VOLUME"
		} else if strings.HasPrefix(clean, "ARG") {
			instType = "ARG"
		} else if strings.HasPrefix(clean, "LABEL") {
			instType = "LABEL"
		} else if strings.HasPrefix(clean, "MAINTAINER") {
			instType = "MAINTAINER"
		}

		// Extract args
		args := strings.TrimSpace(strings.TrimPrefix(clean, instType))

		df.Instructions = append(df.Instructions, Instruction{
			Line: i + 1, // Virtual line number
			Type: instType,
			Args: args,
			Raw:  clean,
		})
	}

	return df
}
