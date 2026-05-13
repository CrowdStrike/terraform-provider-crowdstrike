package correlationrules

// The correlation rules API stores severity as an int32 on a fixed 10/30/50/70/90
// scale. We expose the named levels in Terraform config instead so users don't
// have to memorize the numeric values.

var severityLevels = []struct {
	name string
	api  int32
}{
	{"informational", 10},
	{"low", 30},
	{"medium", 50},
	{"high", 70},
	{"critical", 90},
}

var (
	severityNameToAPI = func() map[string]int32 {
		m := make(map[string]int32, len(severityLevels))
		for _, s := range severityLevels {
			m[s.name] = s.api
		}
		return m
	}()
	severityAPIToName = func() map[int32]string {
		m := make(map[int32]string, len(severityLevels))
		for _, s := range severityLevels {
			m[s.api] = s.name
		}
		return m
	}()
)

func severityNames() []string {
	names := make([]string, len(severityLevels))
	for i, s := range severityLevels {
		names[i] = s.name
	}
	return names
}
