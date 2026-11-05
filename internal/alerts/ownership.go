package alerts

// Notification ownership: Config.MonitorOwns lets the host decide, per rule
// kind, that the Watchtower monitor engine (internal/monitor) already pages
// for the same condition. For such rules the Manager still tracks episodes,
// so ActiveAlerts, Ack, Silence and the infra.alerts.* endpoints behave
// exactly as before, but publish() sends nothing -- one condition, one push.
func (m *Manager) monitorOwns(rule string) bool {
	return m.monitorOwned != nil && m.monitorOwned(rule)
}
