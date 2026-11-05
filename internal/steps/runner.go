package steps

import (
	"context"
	"fmt"
)

// Runner runs catalog steps on the agent side.
type Runner struct {
	Env *Env
}

func (r *Runner) step(id ID) (Step, error) {
	s, ok := Lookup(id)
	if !ok {
		return nil, refuse("%q is not a known fix step.", string(id))
	}
	return s, nil
}

// Validate checks one step's params and that its target exists.
func (r *Runner) Validate(ctx context.Context, id ID, p Params) error {
	s, err := r.step(id)
	if err != nil {
		return err
	}
	return s.Validate(ctx, r.Env, p)
}

// Execute validates and then runs one step. It returns the step's output.
func (r *Runner) Execute(ctx context.Context, id ID, p Params) (string, error) {
	s, err := r.step(id)
	if err != nil {
		return "", err
	}
	if err := s.Validate(ctx, r.Env, p); err != nil {
		return "", err
	}
	return s.Run(ctx, r.Env, p)
}

// Verify checks that one step worked.
func (r *Runner) Verify(ctx context.Context, id ID, p Params) error {
	s, err := r.step(id)
	if err != nil {
		return err
	}
	return s.Verify(ctx, r.Env, p)
}

// Command returns the exact command text shown to the user for a step.
func Command(id ID, p Params) string {
	switch id {
	case ServiceRestartID, ServiceStartID, ServiceStopID, ServiceReloadID:
		verb := string(id)[len("service."):]
		return fmt.Sprintf("systemctl %s %s", verb, p.String("unit"))
	case ContainerRestartID:
		return "docker restart " + p.String("container")
	case ComposeUpID:
		return fmt.Sprintf("docker compose -p %s start %s", p.String("project"), p.String("service"))
	case PM2RestartID:
		return fmt.Sprintf("sudo -u %s pm2 restart %s", p.String("user"), p.String("app"))
	case NginxReloadID:
		return "nginx -t && systemctl reload nginx"
	case PHPFPMRestartID:
		return "systemctl restart " + p.String("unit")
	case SupervisorRestartID:
		return "supervisorctl restart " + p.String("program")
	case JournalVacuumID:
		return "journalctl --vacuum-size=" + p.String("size")
	case DockerPruneID:
		return "docker image prune && docker builder prune"
	case AptCleanID:
		return "apt-get clean"
	case CertRenewID:
		return "certbot renew --cert-name " + p.String("name")
	case ProcessStopID:
		pid, _ := p.Int("pid")
		return fmt.Sprintf("kill -TERM %d", pid)
	case FirewallAllowID:
		port, _ := p.Int("port")
		return fmt.Sprintf("ufw allow %d/%s", port, p.String("proto"))
	case FirewallRemoveID:
		port, _ := p.Int("port")
		return fmt.Sprintf("ufw delete allow %d/%s", port, p.String("proto"))
	case CheckHTTPID:
		return "curl " + p.String("url")
	}
	return string(id)
}
