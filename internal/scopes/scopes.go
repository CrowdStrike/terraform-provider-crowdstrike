package scopes

import (
	"fmt"
	"strings"
)

// CrowdStrike API Scope.
type Scope struct {
	Name  string
	Read  bool
	Write bool
}

// GenerateScopeDescription generates the api scopes block for resource, data-source, and function documentation.
func GenerateScopeDescription(scopes []Scope) string {
	if len(scopes) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## API Scopes\n\nThe following API scopes are required:\n\n")

	for _, scope := range scopes {
		if !scope.Read && !scope.Write {
			continue
		}
		if scope.Read && scope.Write {
			fmt.Fprintf(&sb, "- %s | Read & Write\n", scope.Name)
			continue
		}
		if scope.Write {
			fmt.Fprintf(&sb, "- %s | Write\n", scope.Name)
			continue
		}
		if scope.Read {
			fmt.Fprintf(&sb, "- %s | Read\n", scope.Name)
			continue
		}
	}

	return sb.String()
}
