package paste

// Average returns the mean of values.
func Average(values []int) int {
	sum := 0
	for _, v := range values {
		sum += v
	}
	return sum / len(values)
}
