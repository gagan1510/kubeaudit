package all

import (
	"strings"
	"testing"

	"github.com/gagan1510/kubeaudit"
	"github.com/gagan1510/kubeaudit/auditors/apparmor"
	"github.com/gagan1510/kubeaudit/auditors/asat"
	"github.com/gagan1510/kubeaudit/auditors/capabilities"
	"github.com/gagan1510/kubeaudit/auditors/mounts"

	"github.com/gagan1510/kubeaudit/auditors/hostns"
	"github.com/gagan1510/kubeaudit/auditors/image"
	"github.com/gagan1510/kubeaudit/auditors/limits"
	"github.com/gagan1510/kubeaudit/auditors/netpols"
	"github.com/gagan1510/kubeaudit/auditors/nonroot"
	"github.com/gagan1510/kubeaudit/auditors/privesc"
	"github.com/gagan1510/kubeaudit/auditors/privileged"
	"github.com/gagan1510/kubeaudit/auditors/rootfs"
	"github.com/gagan1510/kubeaudit/auditors/seccomp"
	"github.com/gagan1510/kubeaudit/config"
	"github.com/gagan1510/kubeaudit/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureDir = "../../internal/test/fixtures/all_resources"

func TestAuditAll(t *testing.T) {
	allErrors := []string{
		apparmor.AppArmorAnnotationMissing,
		asat.AutomountServiceAccountTokenTrueAndDefaultSA,
		capabilities.CapabilityOrSecurityContextMissing,
		hostns.NamespaceHostNetworkTrue,
		hostns.NamespaceHostIPCTrue,
		hostns.NamespaceHostPIDTrue,
		image.ImageTagMissing,
		limits.LimitsNotSet,
		netpols.MissingDefaultDenyIngressAndEgressNetworkPolicy,
		nonroot.RunAsNonRootPSCNilCSCNil,
		privesc.AllowPrivilegeEscalationNil,
		privileged.PrivilegedNil,
		rootfs.ReadOnlyRootFilesystemNil,
		seccomp.SeccompAnnotationMissing,
	}

	allAuditors, err := Auditors(config.KubeauditConfig{})
	require.NoError(t, err)

	for _, file := range test.GetAllFileNames(t, fixtureDir) {
		// This line is needed because of how scopes work with parallel tests (see https://gist.github.com/posener/92a55c4cd441fc5e5e85f27bca008721)
		file := file
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			test.AuditMultiple(t, fixtureDir, file, allAuditors, allErrors, "", test.MANIFEST_MODE)
			test.AuditMultiple(t, fixtureDir, file, allAuditors, allErrors, strings.Split(file, ".")[0], test.LOCAL_MODE)
		})
	}
}

func TestFixAll(t *testing.T) {
	allAuditors, err := Auditors(config.KubeauditConfig{})
	require.NoError(t, err)

	files := test.GetAllFileNames(t, fixtureDir)
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			_, report := test.FixSetupMultiple(t, fixtureDir, file, allAuditors)
			for _, result := range report.Results() {
				for _, auditResult := range result.GetAuditResults() {
					require.NotEqual(t, kubeaudit.Error, auditResult.Severity)
				}
			}
		})
	}
}

// Test all auditors with config
func TestAllWithConfig(t *testing.T) {
	enabledAuditors := []string{
		apparmor.Name, seccomp.Name,
	}
	expectedErrors := []string{
		apparmor.AppArmorAnnotationMissing,
		seccomp.SeccompAnnotationMissing,
	}

	conf := config.KubeauditConfig{
		EnabledAuditors: enabledAuditorsToMap(enabledAuditors),
	}
	auditors, err := Auditors(conf)
	require.NoError(t, err)

	for _, file := range test.GetAllFileNames(t, fixtureDir) {
		t.Run(file, func(t *testing.T) {
			test.AuditMultiple(t, fixtureDir, file, auditors, expectedErrors, "", test.MANIFEST_MODE)
		})
	}
}

func TestGetEnabledAuditors(t *testing.T) {
	cases := []struct {
		testName         string
		enabledAuditors  map[string]bool
		expectedAuditors []string
	}{
		{
			// If no config is provided, all auditors should be enabled
			testName:         "No config",
			enabledAuditors:  map[string]bool{},
			expectedAuditors: AuditorNames,
		},
		{
			// If some auditors are explicitly disabled, the rest should default to being enabled
			testName: "Some disabled",
			enabledAuditors: map[string]bool{
				"apparmor": false,
				"rootfs":   false,
			},
			expectedAuditors: []string{
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
				seccomp.Name,
			},
		},
		{
			testName: "Some enabled",
			enabledAuditors: map[string]bool{
				"apparmor": true,
				"rootfs":   true,
			},
			expectedAuditors: AuditorNames,
		},
		{
			// If some auditors are explicitly disabled, the rest should default to being enabled
			testName: "Some enabled, some disabled",
			enabledAuditors: map[string]bool{
				"asat":         true,
				"apparmor":     false,
				"capabilities": true,
				"rootfs":       false,
			},
			expectedAuditors: []string{
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
				seccomp.Name,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.testName, func(t *testing.T) {
			conf := config.KubeauditConfig{
				EnabledAuditors: tc.enabledAuditors,
			}
			got := getEnabledAuditors(conf)
			assert.ElementsMatch(t, got, tc.expectedAuditors)
		})
	}
}

func enabledAuditorsToMap(enabledAuditors []string) map[string]bool {
	enabledAuditorMap := map[string]bool{}
	for _, auditorName := range AuditorNames {
		enabledAuditorMap[auditorName] = false
	}
	for _, auditorName := range enabledAuditors {
		enabledAuditorMap[auditorName] = true
	}
	return enabledAuditorMap
}
