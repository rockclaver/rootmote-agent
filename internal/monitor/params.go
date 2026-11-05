package monitor

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// thresholds returns the firing/recovery pair for a definition, substituting
// the kind's documented defaults for an unset (zero) side so a monitor
// created through the relay without explicit numbers still behaves sanely.
// A recovery value on the wrong side of the firing value would defeat the
// hysteresis band, so it falls back to the default too.
func (d Definition) thresholds(defFire, defRecover float64, higherIsWorse bool) (fire, recover float64) {
	fire, recover = d.FiringThreshold, d.RecoveryValue
	if fire <= 0 {
		fire = defFire
	}
	if recover <= 0 {
		recover = defRecover
	}
	if higherIsWorse && recover > fire {
		recover = fire
	}
	if !higherIsWorse && recover < fire {
		recover = fire
	}
	return fire, recover
}

func (d Definition) param(key string) string {
	return strings.TrimSpace(d.Params[key])
}

// paramFloat reads a positive float param, returning def when unset or
// invalid.
func (d Definition) paramFloat(key string, def float64) float64 {
	v, err := strconv.ParseFloat(d.param(key), 64)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// paramInt reads a positive integer param, returning def when unset or
// invalid.
func (d Definition) paramInt(key string, def int) int {
	v, err := strconv.Atoi(d.param(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// paramDuration reads a duration param, returning def when unset or
// invalid.
func (d Definition) paramDuration(key string, def time.Duration) time.Duration {
	v, err := ParseAge(d.param(key))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// ParseAge parses a Go duration ("90m", "26h") extended with a day suffix
// ("2d", "1d12h"). Shared with the relay's param validation by value, not by
// import: the relay module keeps its own copy of this grammar.
func ParseAge(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var total time.Duration
	if i := strings.Index(s, "d"); i >= 0 {
		days, err := strconv.ParseFloat(s[:i], 64)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		total = time.Duration(days * float64(24*time.Hour))
		s = s[i+1:]
		if s == "" {
			return total, nil
		}
	}
	rest, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return total + rest, nil
}
