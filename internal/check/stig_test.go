package check

import (
	"testing"
	"time"
)

// LOG1b: a log that holds under an hour says so in minutes, not
// "about 0 hours".
func TestDaysShort(t *testing.T) {
	for d, want := range map[time.Duration]string{40 * time.Second: "1 minute", 9 * time.Minute: "9 minutes", 5 * time.Hour: "5 hours", 50 * time.Hour: "2 days"} {
		if got := days(d); got != want {
			t.Errorf("days(%v) = %q, want %q", d, got, want)
		}
	}
}
