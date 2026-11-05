package server

import (
	"fmt"

	"github.com/rockclaver/rootmote-agent/internal/aiproposal"
	"github.com/rockclaver/rootmote-agent/internal/firewall"
	"github.com/rockclaver/rootmote-agent/internal/security"
	"github.com/rockclaver/rootmote-agent/internal/systemd"
)

func serviceLifecycleTokenBinding(unit string, action systemd.Action) (string, string, []string) {
	return "infra.service.action." + string(action), "infra", []string{unit}
}

func processKillTokenBinding(pid int, startTimeTicks uint64, signal string) (string, string, []string) {
	return "infra.process.kill." + signal, "infra", []string{fmt.Sprintf("pid:%d:start:%d", pid, startTimeTicks)}
}

func firewallRuleTokenBinding(verb string, rule firewall.Rule) (string, string, []string) {
	return "infra.firewall." + verb, "infra", []string{fmt.Sprintf("%s/%s/%d", rule.Action, rule.Protocol, rule.Port)}
}

func securityFixTokenBinding(req security.FixRequest) (string, string, []string) {
	file := string(req.Kind)
	if req.Kind == security.FixEnableAuditd {
		file = "auditd"
	}
	return "security.fix." + string(req.Kind), "security", []string{file}
}

func proposalTokenBinding(kind aiproposal.Kind, params map[string]any) (action, projectID string, files []string, err error) {
	switch kind {
	case aiproposal.KindServiceAction:
		name, _ := params["name"].(string)
		actStr, _ := params["action"].(string)
		if name == "" || actStr == "" {
			return "", "", nil, fmt.Errorf("name and action required")
		}
		a, p, f := serviceLifecycleTokenBinding(name, systemd.Action(actStr))
		return a, p, f, nil
	case aiproposal.KindProcessKill:
		pid := intFromParams(params["pid"])
		startTicks := uint64FromParams(params["start_time_ticks"])
		signal, _ := params["signal"].(string)
		if pid <= 0 || startTicks == 0 {
			return "", "", nil, fmt.Errorf("pid and start_time_ticks required")
		}
		a, p, f := processKillTokenBinding(pid, startTicks, signal)
		return a, p, f, nil
	case aiproposal.KindFirewallAdd, aiproposal.KindFirewallRemove:
		rule, rerr := ruleFromParams(params)
		if rerr != nil {
			return "", "", nil, rerr
		}
		verb := "rule_add"
		if kind == aiproposal.KindFirewallRemove {
			verb = "rule_remove"
		}
		a, p, f := firewallRuleTokenBinding(verb, rule)
		return a, p, f, nil
	case aiproposal.KindSecurityFix:
		req, rerr := securityFixRequestFromParams(params)
		if rerr != nil {
			return "", "", nil, rerr
		}
		a, p, f := securityFixTokenBinding(req)
		return a, p, f, nil
	}
	return "", "", nil, fmt.Errorf("unknown kind")
}

func securityFixRequestFromParams(params map[string]any) (security.FixRequest, error) {
	kind, _ := params["kind"].(string)
	if kind == "" {
		return security.FixRequest{}, fmt.Errorf("kind required")
	}
	req := security.FixRequest{
		Kind:           security.FixKind(kind),
		Port:           intFromParams(params["port"]),
		PID:            intFromParams(params["pid"]),
		StartTimeTicks: uint64FromParams(params["start_time_ticks"]),
	}
	req.Protocol, _ = params["protocol"].(string)
	req.Signal, _ = params["signal"].(string)
	switch req.Kind {
	case security.FixClosePort:
		if req.Port <= 0 {
			return security.FixRequest{}, fmt.Errorf("port required")
		}
	case security.FixKillProcess:
		if req.PID <= 0 || req.StartTimeTicks == 0 {
			return security.FixRequest{}, fmt.Errorf("pid and start_time_ticks required")
		}
	case security.FixEnableAuditd:
	case "run_script":
		return security.FixRequest{}, fmt.Errorf("run_script is advice for the operator to run manually; the agent does not execute raw scripts")
	default:
		return security.FixRequest{}, fmt.Errorf("unsupported security fix %q", req.Kind)
	}
	return req, nil
}

func intFromParams(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

func uint64FromParams(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case int:
		return uint64(n)
	case int64:
		return uint64(n)
	case uint64:
		return n
	}
	return 0
}

func ruleFromParams(params map[string]any) (firewall.Rule, error) {
	action, _ := params["action"].(string)
	proto, _ := params["protocol"].(string)
	port := intFromParams(params["port"])
	source, _ := params["source"].(string)
	comment, _ := params["comment"].(string)
	if port <= 0 {
		return firewall.Rule{}, fmt.Errorf("port required")
	}
	if proto == "" {
		proto = string(firewall.ProtoTCP)
	}
	return firewall.Rule{
		Action:   firewall.Action(action),
		Protocol: firewall.Protocol(proto),
		Port:     port,
		Source:   source,
		Comment:  comment,
	}, nil
}
