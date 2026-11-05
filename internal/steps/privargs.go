package steps

import (
	"strconv"
)

// PrivArgs builds the privilege-helper arguments for a root step. The same
// validators the helper runs as root are applied here first, so a bad value
// is refused before sudo is ever called.
func PrivArgs(id ID, p Params) ([]string, error) {
	switch id {
	case ServiceRestartID, ServiceStartID, ServiceStopID, ServiceReloadID:
		unit := p.String("unit")
		if err := CheckUnitAllowed(unit); err != nil {
			return nil, err
		}
		return []string{unit}, nil
	case NginxReloadID, AptCleanID:
		return []string{}, nil
	case PHPFPMRestartID:
		unit := p.String("unit")
		if err := ValidatePHPUnit(unit); err != nil {
			return nil, err
		}
		return []string{unit}, nil
	case SupervisorRestartID:
		prog := p.String("program")
		if err := ValidateName("program", prog); err != nil {
			return nil, err
		}
		return []string{prog}, nil
	case JournalVacuumID:
		size := p.String("size")
		if _, ok := journalSizes[size]; !ok {
			return nil, refuse("The size must be 100M, 200M or 500M.")
		}
		return []string{size}, nil
	case CertRenewID:
		name := p.String("name")
		if err := ValidateCertName(name); err != nil {
			return nil, err
		}
		return []string{name}, nil
	case PM2RestartID:
		user, app := p.String("user"), p.String("app")
		if err := ValidateUser(user); err != nil {
			return nil, err
		}
		if err := ValidateName("app", app); err != nil {
			return nil, err
		}
		return []string{user, app}, nil
	case ProcessStopID:
		pid, ok := p.Int("pid")
		if !ok || pid <= 1 {
			return nil, refuse("The process number is not valid.")
		}
		st, ok := p.Uint("start_time")
		if !ok || st == 0 {
			return nil, refuse("The process start time is not valid.")
		}
		return []string{strconv.FormatInt(pid, 10), strconv.FormatUint(st, 10)}, nil
	case FirewallAllowID, FirewallRemoveID:
		port, ok := p.Int("port")
		if !ok {
			return nil, refuse("The port must be between 1 and 65535.")
		}
		if err := ValidatePort(port); err != nil {
			return nil, err
		}
		proto := p.String("proto")
		if err := ValidateProto(proto); err != nil {
			return nil, err
		}
		return []string{strconv.FormatInt(port, 10), proto}, nil
	}
	return nil, refuse("%s does not run through the privilege helper.", id)
}

var journalSizes = map[string]struct{}{"100M": {}, "200M": {}, "500M": {}}
