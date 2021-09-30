package all

import (
	"errors"
	"fmt"

	"github.com/gagan1510/kubeaudit"
	"github.com/gagan1510/kubeaudit/auditors/apparmor"
	"github.com/gagan1510/kubeaudit/auditors/asat"
	"github.com/gagan1510/kubeaudit/auditors/capabilities"
	"github.com/gagan1510/kubeaudit/auditors/hostns"
	"github.com/gagan1510/kubeaudit/auditors/image"
	"github.com/gagan1510/kubeaudit/auditors/limits"
	"github.com/gagan1510/kubeaudit/auditors/mounts"
	"github.com/gagan1510/kubeaudit/auditors/netpols"
	"github.com/gagan1510/kubeaudit/auditors/nonroot"
	"github.com/gagan1510/kubeaudit/auditors/privesc"
	"github.com/gagan1510/kubeaudit/auditors/privileged"
	"github.com/gagan1510/kubeaudit/auditors/rootfs"
	"github.com/gagan1510/kubeaudit/auditors/seccomp"
	"github.com/gagan1510/kubeaudit/config"
)

var ErrUnknownAuditor = errors.New("Unknown auditor")

var AuditorNames = []string{
	apparmor.Name,
	asat.Name,
	capabilities.Name,
	hostns.Name,
	image.Name,
	limits.Name,
	mounts.Name,
	netpols.Name,
	nonroot.Name,
	privesc.Name,
	privileged.Name,
	rootfs.Name,
	seccomp.Name,
}

func Auditors(conf config.KubeauditConfig) ([]kubeaudit.Auditable, error) {
	auditors := []kubeaudit.Auditable{}
	for _, auditorName := range getEnabledAuditors(conf) {
		auditor, err := initAuditor(auditorName, conf)
		if err != nil {
			return nil, err
		}
		auditors = append(auditors, auditor)
	}

	return auditors, nil
}

// getEnabledAuditors returns a list of all auditors excluding any explicitly disabled in the config
func getEnabledAuditors(conf config.KubeauditConfig) []string {
	auditors := []string{}
	for _, auditorName := range AuditorNames {
		// if value is not found in the `conf.GetEnabledAuditors()` map, this means
		// it wasn't added to the config file, so it should be enabled by default
		if enabled, ok := conf.GetEnabledAuditors()[auditorName]; !ok || enabled {
			auditors = append(auditors, auditorName)
		}
	}
	return auditors
}

func initAuditor(name string, conf config.KubeauditConfig) (kubeaudit.Auditable, error) {
	switch name {
	case apparmor.Name:
		return apparmor.New(), nil
	case asat.Name:
		return asat.New(), nil
	case capabilities.Name:
		return capabilities.New(conf.GetAuditorConfigs().Capabilities), nil
	case hostns.Name:
		return hostns.New(), nil
	case image.Name:
		return image.New(conf.GetAuditorConfigs().Image), nil
	case limits.Name:
		return limits.New(conf.GetAuditorConfigs().Limits)
	case mounts.Name:
		return mounts.New(conf.GetAuditorConfigs().Mounts), nil
	case netpols.Name:
		return netpols.New(), nil
	case nonroot.Name:
		return nonroot.New(), nil
	case privesc.Name:
		return privesc.New(), nil
	case privileged.Name:
		return privileged.New(), nil
	case rootfs.Name:
		return rootfs.New(), nil
	case seccomp.Name:
		return seccomp.New(), nil
	}

	return nil, fmt.Errorf("unknown auditor %s: %w", name, ErrUnknownAuditor)
}
