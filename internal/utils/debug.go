package utils

import (
	"encoding/json"
)

// PancicPrettyPrint converts the interface into a json string and panics.
func PancicPrettyPrint(v interface{}) {
	s, _ := json.MarshalIndent(v, "", "    ") //nolint:errchkjson
	panic(string(s))
}
