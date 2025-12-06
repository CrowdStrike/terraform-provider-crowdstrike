package flex

// Unique returns a new slice containing only the unique elements from the input slice.
// It works for any comparable type E and preserves the order of first occurrence.
func Unique[E comparable](s []E) []E {
	seen := make(map[E]bool)
	var result []E

	for _, item := range s {
		if _, found := seen[item]; !found {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
