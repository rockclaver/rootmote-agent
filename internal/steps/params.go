package steps

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// Params are a step's arguments as they appear in a runbook (JSON values).
type Params map[string]any

// String returns a string param, or "" when it is missing or not a string.
func (p Params) String(name string) string {
	s, _ := p[name].(string)
	return s
}

// Int returns an integer param. JSON numbers decode as float64; whole
// numbers and numeric strings are accepted. ok is false for anything else.
func (p Params) Int(name string) (int64, bool) {
	switch v := p[name].(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case uint64:
		if v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	case float64:
		if v != math.Trunc(v) || math.Abs(v) > 1<<53 {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// Uint returns an unsigned integer param (for process start times).
func (p Params) Uint(name string) (uint64, bool) {
	if v, ok := p[name].(uint64); ok {
		return v, true
	}
	if s, ok := p[name].(string); ok {
		n, err := strconv.ParseUint(s, 10, 64)
		return n, err == nil
	}
	n, ok := p.Int(name)
	if !ok || n < 0 {
		return 0, false
	}
	return uint64(n), true
}

func (p Params) require(names ...string) error {
	for _, n := range names {
		if _, ok := p[n]; !ok {
			return fmt.Errorf("The %q setting is missing.", n)
		}
	}
	return nil
}

func (p Params) clone() Params {
	out := make(Params, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}
