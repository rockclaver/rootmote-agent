package monitor

import "time"

// Silence suppresses the firing and recovery events of one monitor until
// now+d. rule is the monitor kind (for example "disk_capacity") and target
// its target ("/" for the root disk). A non-positive duration clears any
// silence. It returns the absolute expiry, or the zero time when cleared.
func (m *Manager) Silence(rule, target string, d time.Duration) (time.Time, error) {
	k := rule + ":" + target
	if d <= 0 {
		return time.Time{}, m.store.DeleteAlertSilence(k)
	}
	until := m.now().Add(d)
	if err := m.store.PutAlertSilence(k, rule, target, until); err != nil {
		return time.Time{}, err
	}
	return until, nil
}

// Ack records that the operator acknowledged the firing episode of a monitor
// key ("kind:target") that started at firedAt.
func (m *Manager) Ack(key string, firedAt time.Time) error {
	return m.store.PutAlertAck(key, firedAt)
}

func (m *Manager) isSilenced(key string, now time.Time) bool {
	silenced, err := m.store.AlertSilencesActive(now)
	if err != nil {
		m.logf("monitor: read silences: %v", err)
		return false
	}
	_, ok := silenced[key]
	return ok
}
