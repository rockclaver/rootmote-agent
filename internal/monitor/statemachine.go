package monitor

import (
	"time"

	"github.com/rockclaver/rootmote-agent/internal/store"
)

// transition is a firing/resolved state change worth emitting an event for
// -- the only two toState values the wire contract carries.
type transition struct {
	from State
	to   State
}

// stepState advances one (kind,target) runtime node by one observation,
// returning the updated node and a non-nil transition exactly when a
// firing or resolved event must be emitted. now stamps LastTransitionAt on
// every state change so cooldown expiry can be computed lazily on the next
// tick instead of needing a separate persisted deadline.
//
// resolved is not itself terminal: it is held for def.cooldownSeconds()
// (suppressing re-entry into pending the whole time) and lazily promoted to
// healthy the first tick that finds the cooldown has elapsed, before any
// further fail/success processing that same tick.
func stepState(rt store.MonitorState, failing bool, now time.Time, def Definition) (store.MonitorState, *transition) {
	if State(rt.State) == StateResolved {
		cooldown := time.Duration(def.cooldownSeconds()) * time.Second
		if now.Sub(rt.LastTransitionAt) < cooldown {
			return rt, nil
		}
		rt = resetTo(rt, StateHealthy, now)
	}

	switch State(rt.State) {
	case StateFiring:
		return stepFiring(rt, failing, now)
	case StateRecovering:
		return stepRecovering(rt, failing, now, def)
	case StatePending:
		return stepPending(rt, failing, now, def)
	default: // "", unknown, healthy, muted (muted is handled by the caller before stepState runs)
		return stepHealthy(rt, failing, now, def)
	}
}

func resetTo(rt store.MonitorState, s State, now time.Time) store.MonitorState {
	rt.State = string(s)
	rt.ConsecutiveFail = 0
	rt.ConsecutiveOK = 0
	rt.LastTransitionAt = now
	if s == StateHealthy {
		rt.FirstFailureAt = time.Time{}
	}
	return rt
}

func stepHealthy(rt store.MonitorState, failing bool, now time.Time, def Definition) (store.MonitorState, *transition) {
	if !failing {
		if State(rt.State) != StateHealthy {
			rt = resetTo(rt, StateHealthy, now)
		}
		return rt, nil
	}
	rt.State = string(StatePending)
	rt.ConsecutiveFail = 1
	rt.ConsecutiveOK = 0
	rt.FirstFailureAt = now
	rt.LastTransitionAt = now
	if rt.ConsecutiveFail >= def.failureThreshold() {
		from := StatePending
		rt.State = string(StateFiring)
		return rt, &transition{from: from, to: StateFiring}
	}
	return rt, nil
}

func stepPending(rt store.MonitorState, failing bool, now time.Time, def Definition) (store.MonitorState, *transition) {
	if !failing {
		// A single transient failure returns to healthy without emitting:
		// per the contract, "pending --success--> healthy" carries no
		// event.
		return resetTo(rt, StateHealthy, now), nil
	}
	rt.ConsecutiveFail++
	if rt.ConsecutiveFail >= def.failureThreshold() {
		rt.State = string(StateFiring)
		rt.LastTransitionAt = now
		return rt, &transition{from: StatePending, to: StateFiring}
	}
	return rt, nil
}

func stepFiring(rt store.MonitorState, failing bool, now time.Time) (store.MonitorState, *transition) {
	if failing {
		rt.ConsecutiveFail++
		rt.ConsecutiveOK = 0
		return rt, nil
	}
	rt.State = string(StateRecovering)
	rt.ConsecutiveOK = 1
	rt.LastTransitionAt = now
	return rt, nil
}

func stepRecovering(rt store.MonitorState, failing bool, now time.Time, def Definition) (store.MonitorState, *transition) {
	if failing {
		// "recovering --fail--> firing (no new event; already firing)".
		rt.State = string(StateFiring)
		rt.ConsecutiveOK = 0
		rt.LastTransitionAt = now
		return rt, nil
	}
	rt.ConsecutiveOK++
	if rt.ConsecutiveOK >= def.recoveryThreshold() {
		rt.State = string(StateResolved)
		rt.LastTransitionAt = now
		return rt, &transition{from: StateRecovering, to: StateResolved}
	}
	return rt, nil
}
