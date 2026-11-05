package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Step is one catalog entry. Validate checks the params and that the target
// exists right now. Run does the work. Verify checks that it worked. Undo
// names the step that reverses it, or ok=false when it cannot be undone.
type Step interface {
	Def() Def
	Validate(ctx context.Context, env *Env, p Params) error
	Run(ctx context.Context, env *Env, p Params) (string, error)
	Verify(ctx context.Context, env *Env, p Params) error
	Undo(p Params) (ID, Params, bool)
}

var errNoUnits = errors.New("This server's service manager is not available.")

func noUndo(Params) (ID, Params, bool) { return "", nil, false }

func emptyParams() []Param { return []Param{} }

// callPriv validates the params, then runs the helper action named by id.
func callPriv(ctx context.Context, env *Env, id ID, p Params) (string, error) {
	args, err := PrivArgs(id, p)
	if err != nil {
		return "", err
	}
	if env.Priv == nil {
		return "", errors.New("The privilege helper is not available.")
	}
	out, err := env.Priv.Call(ctx, string(id), args...)
	return strings.TrimSpace(string(out)), err
}

// ---- service.* -----------------------------------------------------------

func unitParam() []Param {
	return []Param{nameParam("unit", "units", "systemd unit name")}
}

func validateUnitExists(ctx context.Context, env *Env, p Params) error {
	unit := p.String("unit")
	if err := CheckUnitAllowed(unit); err != nil {
		return err
	}
	if env.Units == nil {
		return errNoUnits
	}
	st, err := env.Units.Status(ctx, unit)
	if err != nil || st.LoadState != "loaded" {
		return refuse("There is no service called %s on this server.", unit)
	}
	return nil
}

func runUnitAction(ctx context.Context, env *Env, p Params, verb string) (string, error) {
	if err := CheckUnitAllowed(p.String("unit")); err != nil {
		return "", err
	}
	if env.Units == nil {
		return "", errNoUnits
	}
	if err := env.Units.Action(ctx, p.String("unit"), verb); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s done.", verb, p.String("unit")), nil
}

func verifyActive(ctx context.Context, env *Env, unit string) (UnitStatus, error) {
	if env.Units == nil {
		return UnitStatus{}, errNoUnits
	}
	st, err := env.Units.Status(ctx, unit)
	if err != nil {
		return st, err
	}
	if st.ActiveState != "active" {
		return st, fmt.Errorf("%s is %s, not active.", unit, st.ActiveState)
	}
	return st, nil
}

// verifyActiveStable checks the unit is active, waits d, and checks it is
// still active and has not restarted on its own in between.
func verifyActiveStable(ctx context.Context, env *Env, unit string, d time.Duration) error {
	first, err := verifyActive(ctx, env, unit)
	if err != nil {
		return err
	}
	env.sleep(ctx, d)
	if err := ctx.Err(); err != nil {
		return err
	}
	second, err := verifyActive(ctx, env, unit)
	if err != nil {
		return err
	}
	if second.NRestarts != first.NRestarts {
		return fmt.Errorf("%s keeps restarting.", unit)
	}
	return nil
}

// ServiceRestart restarts a systemd service.
type ServiceRestart struct{}

func (ServiceRestart) Def() Def {
	return Def{ID: ServiceRestartID, Title: "Restart a service", Description: "Restarts a systemd service.", Root: true,
		Params: unitParam(), Verify: "The service is active and has not restarted for 30 seconds."}
}
func (ServiceRestart) Validate(ctx context.Context, env *Env, p Params) error {
	return validateUnitExists(ctx, env, p)
}
func (ServiceRestart) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return runUnitAction(ctx, env, p, "restart")
}
func (ServiceRestart) Verify(ctx context.Context, env *Env, p Params) error {
	return verifyActiveStable(ctx, env, p.String("unit"), env.serviceStable())
}
func (ServiceRestart) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ServiceStart starts a stopped systemd service.
type ServiceStart struct{}

func (ServiceStart) Def() Def {
	return Def{ID: ServiceStartID, Title: "Start a service", Description: "Starts a systemd service that is stopped.", Root: true,
		Params: unitParam(), Verify: "The service is active.", Undo: ServiceStopID}
}
func (ServiceStart) Validate(ctx context.Context, env *Env, p Params) error {
	return validateUnitExists(ctx, env, p)
}
func (ServiceStart) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return runUnitAction(ctx, env, p, "start")
}
func (ServiceStart) Verify(ctx context.Context, env *Env, p Params) error {
	_, err := verifyActive(ctx, env, p.String("unit"))
	return err
}
func (ServiceStart) Undo(p Params) (ID, Params, bool) { return ServiceStopID, p.clone(), true }

// ServiceStop stops a systemd service.
type ServiceStop struct{}

func (ServiceStop) Def() Def {
	return Def{ID: ServiceStopID, Title: "Stop a service", Description: "Stops a systemd service.", Root: true,
		Params: unitParam(), Verify: "The service is no longer running.", Undo: ServiceStartID}
}
func (ServiceStop) Validate(ctx context.Context, env *Env, p Params) error {
	return validateUnitExists(ctx, env, p)
}
func (ServiceStop) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return runUnitAction(ctx, env, p, "stop")
}
func (ServiceStop) Verify(ctx context.Context, env *Env, p Params) error {
	if env.Units == nil {
		return errNoUnits
	}
	st, err := env.Units.Status(ctx, p.String("unit"))
	if err != nil {
		return err
	}
	if st.ActiveState == "active" || st.ActiveState == "activating" {
		return fmt.Errorf("%s is still running.", p.String("unit"))
	}
	return nil
}
func (ServiceStop) Undo(p Params) (ID, Params, bool) { return ServiceStartID, p.clone(), true }

// ServiceReload asks a service to reload its settings.
type ServiceReload struct{}

func (ServiceReload) Def() Def {
	return Def{ID: ServiceReloadID, Title: "Reload a service", Description: "Asks a systemd service to reload its settings without stopping.", Root: true,
		Params: unitParam(), Verify: "The service is active."}
}
func (ServiceReload) Validate(ctx context.Context, env *Env, p Params) error {
	return validateUnitExists(ctx, env, p)
}
func (ServiceReload) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return runUnitAction(ctx, env, p, "reload")
}
func (ServiceReload) Verify(ctx context.Context, env *Env, p Params) error {
	_, err := verifyActive(ctx, env, p.String("unit"))
	return err
}
func (ServiceReload) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ---- docker --------------------------------------------------------------

func findContainer(ctx context.Context, env *Env, name string) (ContainerInfo, error) {
	if env.Docker == nil {
		return ContainerInfo{}, errors.New("Docker is not available on this server.")
	}
	list, err := env.Docker.Containers(ctx)
	if err != nil {
		return ContainerInfo{}, err
	}
	for _, c := range list {
		if c.Name == name || c.ID == name {
			return c, nil
		}
	}
	return ContainerInfo{}, refuse("There is no container called %s.", name)
}

// ContainerRestart restarts a Docker container through the Docker API.
type ContainerRestart struct{}

func (ContainerRestart) Def() Def {
	return Def{ID: ContainerRestartID, Title: "Restart a container", Description: "Restarts a Docker container.",
		Params: []Param{nameParam("container", "containers", "Docker container name")},
		Verify: "The container is running and has not restarted for 60 seconds."}
}
func (ContainerRestart) Validate(ctx context.Context, env *Env, p Params) error {
	if err := ValidateName("container", p.String("container")); err != nil {
		return err
	}
	_, err := findContainer(ctx, env, p.String("container"))
	return err
}
func (ContainerRestart) Run(ctx context.Context, env *Env, p Params) (string, error) {
	c, err := findContainer(ctx, env, p.String("container"))
	if err != nil {
		return "", err
	}
	if err := env.Docker.Restart(ctx, c.ID); err != nil {
		return "", err
	}
	return "Restarted container " + c.Name + ".", nil
}
func (ContainerRestart) Verify(ctx context.Context, env *Env, p Params) error {
	first, err := findContainer(ctx, env, p.String("container"))
	if err != nil {
		return err
	}
	if first.State != "running" {
		return fmt.Errorf("%s is %s, not running.", first.Name, first.State)
	}
	env.sleep(ctx, env.containerStable())
	if err := ctx.Err(); err != nil {
		return err
	}
	second, err := findContainer(ctx, env, p.String("container"))
	if err != nil {
		return err
	}
	if second.State != "running" {
		return fmt.Errorf("%s stopped again (%s).", second.Name, second.State)
	}
	if second.RestartCount != first.RestartCount {
		return fmt.Errorf("%s keeps restarting.", second.Name)
	}
	return nil
}
func (ContainerRestart) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

const (
	labelComposeDir    = "com.docker.compose.project.working_dir"
	labelComposeHash   = "com.docker.compose.config-hash"
	labelComposeOneoff = "com.docker.compose.oneoff"
)

// composeContainers returns the long-running containers of one Compose
// service. One-off containers (`docker compose run`) are not part of it.
func composeContainers(ctx context.Context, env *Env, project, service string) ([]ContainerInfo, error) {
	if env.Docker == nil {
		return nil, errors.New("Docker is not available on this server.")
	}
	list, err := env.Docker.Containers(ctx)
	if err != nil {
		return nil, err
	}
	var out []ContainerInfo
	for _, c := range list {
		if c.ComposeProject == project && c.ComposeService == service && !strings.EqualFold(c.Labels[labelComposeOneoff], "true") {
			out = append(out, c)
		}
	}
	return out, nil
}

// composeTargets returns the existing containers of a Compose service. They
// must all come from the same Compose configuration (one config hash and one
// project folder), so a container that only borrowed the labels cannot take
// the place of the real one.
func composeTargets(ctx context.Context, env *Env, project, service string) ([]ContainerInfo, error) {
	if err := ValidateName("project", project); err != nil {
		return nil, err
	}
	if err := ValidateName("service", service); err != nil {
		return nil, err
	}
	cs, err := composeContainers(ctx, env, project, service)
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, refuse("This service has no containers to start. Run docker compose up for this project yourself.")
	}
	hash, dir := cs[0].Labels[labelComposeHash], cs[0].Labels[labelComposeDir]
	if hash == "" || dir == "" {
		return nil, refuse("These containers do not say which Compose configuration made them, so Rootmote will not start them.")
	}
	for _, c := range cs[1:] {
		if c.Labels[labelComposeHash] != hash || c.Labels[labelComposeDir] != dir {
			return nil, refuse("The containers of this service come from different Compose configurations, so Rootmote will not start them.")
		}
	}
	return cs, nil
}

// ComposeUp starts the existing containers of one Compose service. It never
// reads or runs a Compose file.
type ComposeUp struct{}

func (ComposeUp) Def() Def {
	return Def{ID: ComposeUpID, Title: "Start a Compose service", Description: "Starts the existing containers of one Docker Compose service. It does not read or change the Compose files.",
		Params: []Param{
			nameParam("project", "compose_services", "Docker Compose project name"),
			nameParam("service", "compose_services", "service name inside the Compose project"),
		},
		Verify: "The service's containers are running and healthy."}
}
func (ComposeUp) Validate(ctx context.Context, env *Env, p Params) error {
	_, err := composeTargets(ctx, env, p.String("project"), p.String("service"))
	return err
}

func (ComposeUp) Run(ctx context.Context, env *Env, p Params) (string, error) {
	cs, err := composeTargets(ctx, env, p.String("project"), p.String("service"))
	if err != nil {
		return "", err
	}
	for _, c := range cs {
		switch {
		case c.State == "running" && c.Health != "unhealthy":
			// Already up.
		case c.State == "exited" || c.State == "created" || c.State == "dead":
			if err := env.Docker.Start(ctx, c.ID); err != nil {
				return "", err
			}
		default:
			if err := env.Docker.Restart(ctx, c.ID); err != nil {
				return "", err
			}
		}
	}
	return fmt.Sprintf("Started %s in project %s.", p.String("service"), p.String("project")), nil
}

// composeHealthPolls is how many 2-second polls ComposeUp.Verify allows a
// container whose health check is still "starting" (a fresh container always
// begins there) before it gives up: 90 seconds in all.
const composeHealthPolls = 45

// composeSettle is how long ComposeUp.Verify waits before it checks that the
// container has not restarted again.
const composeSettle = 5 * time.Second

func (ComposeUp) Verify(ctx context.Context, env *Env, p Params) error {
	var settled map[string]int // restart counts seen when everything first looked fine
	for poll := 0; ; poll++ {
		cs, err := composeContainers(ctx, env, p.String("project"), p.String("service"))
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			return fmt.Errorf("No container found for %s.", p.String("service"))
		}
		starting := ""
		for _, c := range cs {
			if c.State != "running" {
				return fmt.Errorf("%s is %s, not running.", c.Name, c.State)
			}
			switch c.Health {
			case "", "healthy":
			case "starting":
				starting = c.Name
			default:
				return fmt.Errorf("%s is %s.", c.Name, c.Health)
			}
		}
		if starting == "" {
			// A crash-looping container is "running" between crashes, so
			// look again a few seconds later and require no new restarts.
			if settled != nil {
				for _, c := range cs {
					if n, ok := settled[c.ID]; !ok || n != c.RestartCount {
						return fmt.Errorf("%s keeps restarting.", c.Name)
					}
				}
				return nil
			}
			settled = map[string]int{}
			for _, c := range cs {
				settled[c.ID] = c.RestartCount
			}
			env.sleep(ctx, composeSettle)
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}
		settled = nil
		if poll >= composeHealthPolls {
			return fmt.Errorf("%s is still starting its health check.", starting)
		}
		env.sleep(ctx, 2*time.Second)
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}
func (ComposeUp) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ---- pm2 / supervisor / php / nginx ---------------------------------------

type pm2App struct {
	App      string `json:"app"`
	Status   string `json:"status"`
	Restarts int    `json:"restarts"`
}

func pm2List(ctx context.Context, env *Env, user string) ([]pm2App, error) {
	if env.Priv == nil {
		return nil, errors.New("The privilege helper is not available.")
	}
	out, err := env.Priv.Call(ctx, "pm2-list", user)
	if err != nil {
		return nil, err
	}
	var apps []pm2App
	if err := json.Unmarshal(out, &apps); err != nil {
		return nil, errors.New("Could not read the PM2 app list.")
	}
	return apps, nil
}

func pm2Find(ctx context.Context, env *Env, user, app string) (pm2App, error) {
	apps, err := pm2List(ctx, env, user)
	if err != nil {
		return pm2App{}, err
	}
	for _, a := range apps {
		if a.App == app {
			return a, nil
		}
	}
	return pm2App{}, refuse("There is no PM2 app called %s for user %s.", app, user)
}

// PM2Restart restarts a PM2 app as its owner.
type PM2Restart struct{}

func (PM2Restart) Def() Def {
	return Def{ID: PM2RestartID, Title: "Restart a PM2 app", Description: "Restarts a PM2 app as the user who owns it.", Root: true,
		Params: []Param{
			nameParam("app", "pm2_apps", "PM2 app name"),
			nameParam("user", "pm2_apps", "login user that owns the PM2 app"),
		},
		Verify: "The app is online and has not restarted for 60 seconds."}
}
func (PM2Restart) Validate(ctx context.Context, env *Env, p Params) error {
	if _, err := PrivArgs(PM2RestartID, p); err != nil {
		return err
	}
	_, err := pm2Find(ctx, env, p.String("user"), p.String("app"))
	return err
}
func (PM2Restart) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, PM2RestartID, p)
}
func (PM2Restart) Verify(ctx context.Context, env *Env, p Params) error {
	first, err := pm2Find(ctx, env, p.String("user"), p.String("app"))
	if err != nil {
		return err
	}
	if first.Status != "online" {
		return fmt.Errorf("%s is %s, not online.", first.App, first.Status)
	}
	env.sleep(ctx, env.pm2Stable())
	if err := ctx.Err(); err != nil {
		return err
	}
	second, err := pm2Find(ctx, env, p.String("user"), p.String("app"))
	if err != nil {
		return err
	}
	if second.Status != "online" {
		return fmt.Errorf("%s went %s again.", second.App, second.Status)
	}
	if second.Restarts != first.Restarts {
		return fmt.Errorf("%s keeps restarting.", second.App)
	}
	return nil
}
func (PM2Restart) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// NginxReload tests the nginx settings, then reloads nginx.
type NginxReload struct{}

func (NginxReload) Def() Def {
	return Def{ID: NginxReloadID, Title: "Reload nginx", Description: "Tests the nginx settings, then reloads nginx only if the test passes.", Root: true,
		Params: emptyParams(), Verify: "nginx is active and its settings test passes."}
}
func (NginxReload) Validate(ctx context.Context, env *Env, p Params) error {
	if env.Units == nil {
		return errNoUnits
	}
	st, err := env.Units.Status(ctx, "nginx.service")
	if err != nil || st.LoadState != "loaded" {
		return refuse("nginx is not installed on this server.")
	}
	return nil
}
func (NginxReload) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, NginxReloadID, p)
}
func (NginxReload) Verify(ctx context.Context, env *Env, p Params) error {
	if _, err := verifyActive(ctx, env, "nginx.service"); err != nil {
		return err
	}
	if env.Priv == nil {
		return errors.New("The privilege helper is not available.")
	}
	if _, err := env.Priv.Call(ctx, "nginx-test"); err != nil {
		return fmt.Errorf("The nginx settings test failed: %w", err)
	}
	return nil
}
func (NginxReload) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// PHPFPMRestart restarts a PHP-FPM service.
type PHPFPMRestart struct{}

func (PHPFPMRestart) Def() Def {
	return Def{ID: PHPFPMRestartID, Title: "Restart PHP-FPM", Description: "Restarts a PHP-FPM service such as php8.3-fpm.", Root: true,
		Params: []Param{{Name: "unit", Type: "string", Pattern: phpPattern, Enum: []string{}, Source: "units", Description: "PHP-FPM unit name"}},
		Verify: "The service is active."}
}
func (PHPFPMRestart) Validate(ctx context.Context, env *Env, p Params) error {
	if err := ValidatePHPUnit(p.String("unit")); err != nil {
		return err
	}
	return validateUnitExists(ctx, env, p)
}
func (PHPFPMRestart) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, PHPFPMRestartID, p)
}
func (PHPFPMRestart) Verify(ctx context.Context, env *Env, p Params) error {
	_, err := verifyActive(ctx, env, p.String("unit"))
	return err
}
func (PHPFPMRestart) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

type supervisorProgram struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

func supervisorList(ctx context.Context, env *Env) ([]supervisorProgram, error) {
	if env.Priv == nil {
		return nil, errors.New("The privilege helper is not available.")
	}
	out, err := env.Priv.Call(ctx, "supervisor-status")
	if err != nil {
		return nil, err
	}
	var list []supervisorProgram
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, errors.New("Could not read the Supervisor program list.")
	}
	return list, nil
}

// MatchSupervisor returns the processes that belong to a program: the exact
// name, or every member of a group named program.
func MatchSupervisor(list []supervisorProgram, program string) []supervisorProgram {
	var out []supervisorProgram
	for _, s := range list {
		if s.Name == program || strings.HasPrefix(s.Name, program+":") {
			out = append(out, s)
		}
	}
	return out
}

func supervisorRunning(ctx context.Context, env *Env, program string) error {
	list, err := supervisorList(ctx, env)
	if err != nil {
		return err
	}
	m := MatchSupervisor(list, program)
	if len(m) == 0 {
		return refuse("There is no Supervisor program called %s.", program)
	}
	for _, s := range m {
		if s.State != "RUNNING" {
			return fmt.Errorf("%s is %s.", s.Name, s.State)
		}
	}
	return nil
}

// SupervisorRestart restarts a Supervisor program.
type SupervisorRestart struct{}

func (SupervisorRestart) Def() Def {
	return Def{ID: SupervisorRestartID, Title: "Restart a Supervisor program", Description: "Restarts a program managed by Supervisor, such as a queue worker.", Root: true,
		Params: []Param{nameParam("program", "supervisor_programs", "Supervisor program or group name")},
		Verify: "The program shows RUNNING for 30 seconds."}
}
func (SupervisorRestart) Validate(ctx context.Context, env *Env, p Params) error {
	if _, err := PrivArgs(SupervisorRestartID, p); err != nil {
		return err
	}
	list, err := supervisorList(ctx, env)
	if err != nil {
		return err
	}
	if len(MatchSupervisor(list, p.String("program"))) == 0 {
		return refuse("There is no Supervisor program called %s.", p.String("program"))
	}
	return nil
}
func (SupervisorRestart) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, SupervisorRestartID, p)
}
func (SupervisorRestart) Verify(ctx context.Context, env *Env, p Params) error {
	if err := supervisorRunning(ctx, env, p.String("program")); err != nil {
		return err
	}
	env.sleep(ctx, env.supervisorStable())
	if err := ctx.Err(); err != nil {
		return err
	}
	return supervisorRunning(ctx, env, p.String("program"))
}
func (SupervisorRestart) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ---- disk ----------------------------------------------------------------

// JournalDir is where journald keeps its logs; disk.journal_vacuum frees space there.
const JournalDir = "/var/log/journal"

// AptCacheDir is where apt keeps downloaded packages; disk.apt_clean frees space there.
const AptCacheDir = "/var/cache/apt"

// DiskStepPath returns the folder a disk step frees space in. It is empty and
// the error says why when the folder is not known (Docker not reachable).
func DiskStepPath(ctx context.Context, env *Env, id ID) (string, error) {
	switch id {
	case JournalVacuumID:
		return JournalDir, nil
	case AptCleanID:
		return AptCacheDir, nil
	case DockerPruneID:
		if env == nil || env.Docker == nil {
			return "", errors.New("Docker is not available on this server.")
		}
		dir, err := env.Docker.RootDir(ctx)
		if err != nil {
			return "", err
		}
		if dir == "" {
			return "", errors.New("Docker did not report where it keeps its data.")
		}
		return dir, nil
	}
	return "", fmt.Errorf("%s does not free disk space.", id)
}

// verifyDisk checks the mount that holds the folder the step freed space in.
func verifyDisk(ctx context.Context, env *Env, id ID) error {
	if env.DiskPercentAt == nil {
		return errors.New("Disk usage is not available.")
	}
	dir, err := DiskStepPath(ctx, env, id)
	if err != nil {
		return err
	}
	pct, err := env.DiskPercentAt(ctx, dir)
	if err != nil {
		return err
	}
	if pct >= DiskThresholdPercent {
		return fmt.Errorf("The disk that holds %s is still %.0f%% full.", dir, pct)
	}
	return nil
}

// JournalVacuum shrinks the systemd journal.
type JournalVacuum struct{}

func (JournalVacuum) Def() Def {
	return Def{ID: JournalVacuumID, Title: "Shrink system logs", Description: "Deletes the oldest systemd journal logs until they fit in the chosen size.", Root: true,
		Params: []Param{{Name: "size", Type: "string", Pattern: sizePattern, Enum: []string{"100M", "200M", "500M"}, Source: "none", Description: "largest size to keep"}},
		Verify: "Disk usage is below 85 percent."}
}
func (JournalVacuum) Validate(_ context.Context, _ *Env, p Params) error {
	_, err := PrivArgs(JournalVacuumID, p)
	return err
}
func (JournalVacuum) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, JournalVacuumID, p)
}
func (JournalVacuum) Verify(ctx context.Context, env *Env, _ Params) error {
	return verifyDisk(ctx, env, JournalVacuumID)
}
func (JournalVacuum) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// DockerPrune removes dangling images and unused build cache. Never volumes.
type DockerPrune struct{}

func (DockerPrune) Def() Def {
	return Def{ID: DockerPruneID, Title: "Remove unused Docker data", Description: "Deletes dangling Docker images and unused build cache. Volumes and containers are never touched.",
		Params: emptyParams(), Verify: "Disk usage is below 85 percent."}
}
func (DockerPrune) Validate(_ context.Context, env *Env, _ Params) error {
	if env.Docker == nil {
		return errors.New("Docker is not available on this server.")
	}
	return nil
}
func (DockerPrune) Run(ctx context.Context, env *Env, _ Params) (string, error) {
	if env.Docker == nil {
		return "", errors.New("Docker is not available on this server.")
	}
	freed, err := env.Docker.PruneDangling(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Freed %d MB of Docker images and build cache.", freed/(1<<20)), nil
}
func (DockerPrune) Verify(ctx context.Context, env *Env, _ Params) error {
	return verifyDisk(ctx, env, DockerPruneID)
}
func (DockerPrune) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// AptClean clears the apt package cache.
type AptClean struct{}

func (AptClean) Def() Def {
	return Def{ID: AptCleanID, Title: "Clear the package cache", Description: "Runs apt-get clean to delete downloaded package files.", Root: true,
		Params: emptyParams(), Verify: "Disk usage is below 85 percent."}
}
func (AptClean) Validate(context.Context, *Env, Params) error { return nil }
func (AptClean) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, AptCleanID, p)
}
func (AptClean) Verify(ctx context.Context, env *Env, _ Params) error {
	return verifyDisk(ctx, env, AptCleanID)
}
func (AptClean) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ---- certificates ---------------------------------------------------------

type certInfo struct {
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func certList(ctx context.Context, env *Env) ([]certInfo, error) {
	if env.Priv == nil {
		return nil, errors.New("The privilege helper is not available.")
	}
	out, err := env.Priv.Call(ctx, "certs-list")
	if err != nil {
		return nil, err
	}
	var list []certInfo
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, errors.New("Could not read the certificate list.")
	}
	return list, nil
}

// CertRenew renews a Let's Encrypt certificate.
type CertRenew struct{}

func (CertRenew) Def() Def {
	return Def{ID: CertRenewID, Title: "Renew a certificate", Description: "Renews a Let's Encrypt certificate with certbot, then reloads nginx if it is installed.", Root: true,
		Params: []Param{{Name: "name", Type: "string", Pattern: certPattern, Enum: []string{}, Source: "certs", Description: "certificate name"}},
		Verify: "The new expiry date is more than 30 days away."}
}
func (CertRenew) Validate(ctx context.Context, env *Env, p Params) error {
	if err := ValidateCertName(p.String("name")); err != nil {
		return err
	}
	list, err := certList(ctx, env)
	if err != nil {
		return err
	}
	for _, c := range list {
		if c.Name == p.String("name") {
			return nil
		}
	}
	return refuse("There is no certificate called %s on this server.", p.String("name"))
}
func (CertRenew) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, CertRenewID, p)
}
func (CertRenew) Verify(ctx context.Context, env *Env, p Params) error {
	list, err := certList(ctx, env)
	if err != nil {
		return err
	}
	for _, c := range list {
		if c.Name != p.String("name") {
			continue
		}
		days := c.ExpiresAt.Sub(env.now()).Hours() / 24
		if days <= CertMinDays {
			return fmt.Errorf("The certificate still expires in %.0f days.", days)
		}
		return nil
	}
	return refuse("There is no certificate called %s on this server.", p.String("name"))
}
func (CertRenew) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ---- process --------------------------------------------------------------

// ProcessStop stops one process.
type ProcessStop struct{}

func (ProcessStop) Def() Def {
	return Def{ID: ProcessStopID, Title: "Stop a process", Description: "Sends a polite stop signal to one process, then forces it to end after 10 seconds if it is still running.", Root: true,
		Params: []Param{
			{Name: "pid", Type: "integer", Pattern: "", Enum: []string{}, Source: "none", Description: "process number"},
			{Name: "start_time", Type: "integer", Pattern: "", Enum: []string{}, Source: "none", Description: "process start time in clock ticks, from the process list; protects against a reused process number"},
		},
		Verify: "The process is gone."}
}
func (ProcessStop) Validate(ctx context.Context, env *Env, p Params) error {
	args, err := PrivArgs(ProcessStopID, p)
	if err != nil {
		return err
	}
	if env.Procs == nil {
		return nil
	}
	pid, _ := p.Int("pid")
	want, _ := p.Uint("start_time")
	ticks, alive := env.Procs.StartTime(int(pid))
	if !alive {
		return refuse("Process %s is not running.", args[0])
	}
	if ticks != want {
		return refuse("Process %s is no longer the same program.", args[0])
	}
	return nil
}
func (ProcessStop) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, ProcessStopID, p)
}
func (ProcessStop) Verify(ctx context.Context, env *Env, p Params) error {
	if env.Procs == nil {
		return errors.New("Process information is not available.")
	}
	pid, _ := p.Int("pid")
	want, _ := p.Uint("start_time")
	if ticks, alive := env.Procs.StartTime(int(pid)); alive && ticks == want {
		return fmt.Errorf("Process %d is still running.", pid)
	}
	return nil
}
func (ProcessStop) Undo(p Params) (ID, Params, bool) { return noUndo(p) }

// ---- firewall -------------------------------------------------------------

type firewallRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

func firewallHas(ctx context.Context, env *Env, p Params) (bool, error) {
	if env.Priv == nil {
		return false, errors.New("The privilege helper is not available.")
	}
	out, err := env.Priv.Call(ctx, "firewall-rules")
	if err != nil {
		return false, err
	}
	var rules []firewallRule
	if err := json.Unmarshal(out, &rules); err != nil {
		return false, errors.New("Could not read the firewall rules.")
	}
	port, _ := p.Int("port")
	for _, r := range rules {
		if int64(r.Port) == port && r.Proto == p.String("proto") {
			return true, nil
		}
	}
	return false, nil
}

func firewallParams() []Param { return []Param{portParam(), protoParam()} }

// FirewallAllow opens a firewall port.
type FirewallAllow struct{}

func (FirewallAllow) Def() Def {
	return Def{ID: FirewallAllowID, Title: "Open a firewall port", Description: "Adds a firewall rule that allows traffic to one port.", Root: true,
		Params: firewallParams(), Verify: "The firewall rule is present.", Undo: FirewallRemoveID}
}
func (FirewallAllow) Validate(_ context.Context, _ *Env, p Params) error {
	_, err := PrivArgs(FirewallAllowID, p)
	return err
}
func (FirewallAllow) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, FirewallAllowID, p)
}
func (FirewallAllow) Verify(ctx context.Context, env *Env, p Params) error {
	ok, err := firewallHas(ctx, env, p)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("The firewall rule was not found.")
	}
	return nil
}
func (FirewallAllow) Undo(p Params) (ID, Params, bool) { return FirewallRemoveID, p.clone(), true }

// FirewallRemove closes a firewall port.
type FirewallRemove struct{}

func (FirewallRemove) Def() Def {
	return Def{ID: FirewallRemoveID, Title: "Close a firewall port", Description: "Removes a firewall rule that allows traffic to one port. The SSH port is never closed.", Root: true,
		Params: firewallParams(), Verify: "The firewall rule is gone.", Undo: FirewallAllowID}
}
func (FirewallRemove) Validate(_ context.Context, _ *Env, p Params) error {
	_, err := PrivArgs(FirewallRemoveID, p)
	return err
}
func (FirewallRemove) Run(ctx context.Context, env *Env, p Params) (string, error) {
	return callPriv(ctx, env, FirewallRemoveID, p)
}
func (FirewallRemove) Verify(ctx context.Context, env *Env, p Params) error {
	ok, err := firewallHas(ctx, env, p)
	if err != nil {
		return err
	}
	if ok {
		return errors.New("The firewall rule is still there.")
	}
	return nil
}
func (FirewallRemove) Undo(p Params) (ID, Params, bool) { return FirewallAllowID, p.clone(), true }

// ---- check.http -----------------------------------------------------------

// CheckHTTP makes a GET request to an address on this host.
type CheckHTTP struct{}

func (CheckHTTP) Def() Def {
	return Def{ID: CheckHTTPID, Title: "Check a web address", Description: "Requests a web address on this server and checks that it answers.",
		Params: []Param{{Name: "url", Type: "string", Pattern: urlPattern, Enum: []string{}, Source: "urls", Description: "web address on this server"}},
		Verify: "The address answers with a success or redirect status."}
}
func (CheckHTTP) Validate(_ context.Context, env *Env, p Params) error {
	raw := p.String("url")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return refuse("That web address is not allowed.")
	}
	if env.AllowedURL == nil || !env.AllowedURL(raw) {
		return refuse("Rootmote only checks web addresses that belong to this server.")
	}
	return nil
}
func (c CheckHTTP) Run(ctx context.Context, env *Env, p Params) (string, error) {
	status, err := c.get(ctx, env, p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s answered %d.", p.String("url"), status), nil
}
func (c CheckHTTP) get(ctx context.Context, env *Env, p Params) (int, error) {
	if err := c.Validate(ctx, env, p); err != nil {
		return 0, err
	}
	if env.HTTP == nil {
		return 0, errors.New("Web checks are not available.")
	}
	status, err := env.HTTP.Get(ctx, p.String("url"))
	if err != nil {
		return 0, fmt.Errorf("The address did not answer: %w", err)
	}
	if status < 200 || status >= 400 {
		return status, fmt.Errorf("The address answered with status %d.", status)
	}
	return status, nil
}
func (c CheckHTTP) Verify(ctx context.Context, env *Env, p Params) error {
	_, err := c.get(ctx, env, p)
	return err
}
func (CheckHTTP) Undo(p Params) (ID, Params, bool) { return noUndo(p) }
