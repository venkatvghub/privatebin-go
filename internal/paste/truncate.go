package paste

// Truncate returns the first n bytes of s.
func Truncate(s string, n int) string {
	return s[:n]
}
