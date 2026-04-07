// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package otelagent contains e2e otel agent tests
package otelagent

import (
	_ "embed"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes/core/v1"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/DataDog/datadog-agent/test/e2e-framework/common/config"
	"github.com/DataDog/datadog-agent/test/e2e-framework/components/datadog/agent"
	fakeintakeComp "github.com/DataDog/datadog-agent/test/e2e-framework/components/datadog/fakeintake"
	otelstandalone "github.com/DataDog/datadog-agent/test/e2e-framework/components/datadog/otel-standalone"
	scenkindvm "github.com/DataDog/datadog-agent/test/e2e-framework/scenarios/aws/kindvm"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/e2e"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/environments"
	provkindvm "github.com/DataDog/datadog-agent/test/e2e-framework/testing/provisioners/aws/kubernetes/kindvm"
	provlocal "github.com/DataDog/datadog-agent/test/e2e-framework/testing/provisioners/local/kubernetes"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/provisioners"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/otel/utils"

	"github.com/pulumi/pulumi-kubernetes/sdk/v4/go/kubernetes"
)

const (
	dogtelSecretsNamespace = "datadog"
	dogtelSecretsName      = "dogtel-secrets"
	// dogtelResolvedHostname is the hostname value stored in the K8s secret.
	// If secretsfx.Module() is active the ENC[] handle resolves to this value;
	// the noop impl would leave the raw "ENC[file@...]" literal unchanged.
	dogtelResolvedHostname = "dogtel-secrets-test-host"
)

// dogtelSecretsConfig is the OTel config for the secrets test.  It uses
// allow_hostname_override: true on the infraattributes processor so that the
// processor injects "datadog.host.name" (set to the agent's resolved hostname)
// into span resource attributes.  This attribute takes priority over k8s.node.name
// in the trace-agent hostname detection, making it possible to verify that an
// ENC[] handle in DD_HOSTNAME was actually resolved (tp.Hostname == resolved value)
// rather than being silently overridden by the K8s node name.
//
//go:embed config/dogtel-secrets.yml
var dogtelSecretsConfig string

// dogtelSecretsTestSuite verifies that secretsfx.Module() (real secrets) is wired
// when DD_OTEL_STANDALONE=true by confirming ENC[] handle resolution end-to-end.
type dogtelSecretsTestSuite struct {
	e2e.BaseSuite[environments.Kubernetes]
}

// dogtelSecretsStandaloneProvisioner returns a provisioner that deploys the
// otel-agent as a standalone DaemonSet (no core agent, no Helm chart) with:
//   - A Kubernetes secret pre-created containing the resolved hostname
//   - DD_SECRET_BACKEND_COMMAND pointing at the built-in multi-provider script
//   - DD_HOSTNAME=ENC[file@...] referencing the secret
//
// Using the standalone DaemonSet avoids sidecar interference: in Helm sidecar
// mode the core agent's hostname resolution can shadow the otel-agent container's
// own DD_HOSTNAME env var.
func dogtelSecretsStandaloneProvisioner() provisioners.TypedProvisioner[environments.Kubernetes] {
	deployFn := func(e config.Env, kubeProvider *kubernetes.Provider, fi *fakeintakeComp.Fakeintake) (*agent.KubernetesAgent, error) {
		return otelstandalone.K8sAppDefinition(
			e, kubeProvider, dogtelSecretsNamespace, dogtelSecretsConfig, fi,
			// Pre-create the K8s secret so it is mounted when the pod starts.
			otelstandalone.WithK8sSecret(dogtelSecretsName, map[string]string{
				"hostname": dogtelResolvedHostname,
			}),
			// Supply DD_HOSTNAME via ENC[] before the default downward-API entry.
			// WithoutDefaultHostname() prevents the downward-API spec.nodeName
			// entry from being added; Go's os.Getenv returns the first match, so
			// the extra env vars must come first — which K8sAppDefinition guarantees.
			otelstandalone.WithoutDefaultHostname(),
			otelstandalone.WithExtraEnvVars(
				&corev1.EnvVarArgs{
					Name:  pulumi.String("DD_HOSTNAME"),
					Value: pulumi.String("ENC[file@/etc/dogtel-secrets/hostname]"),
				},
				&corev1.EnvVarArgs{
					Name:  pulumi.String("DD_SECRET_BACKEND_COMMAND"),
					Value: pulumi.String("/readsecret_multiple_providers.sh"),
				},
			),
			// Mount the K8s secret into the container.
			otelstandalone.WithExtraVolumes(
				&corev1.VolumeArgs{
					Name: pulumi.String(dogtelSecretsName),
					Secret: &corev1.SecretVolumeSourceArgs{
						SecretName: pulumi.String(dogtelSecretsName),
					},
				},
			),
			otelstandalone.WithExtraVolumeMounts(
				&corev1.VolumeMountArgs{
					Name:      pulumi.String(dogtelSecretsName),
					MountPath: pulumi.String("/etc/dogtel-secrets"),
					ReadOnly:  pulumi.BoolPtr(true),
				},
			),
		)
	}

	if isKindLocal() {
		return provlocal.Provisioner(
			provlocal.WithStandaloneOTelAgent(deployFn),
		)
	}
	return provkindvm.Provisioner(
		provkindvm.WithRunOptions(
			scenkindvm.WithStandaloneOTelAgent(deployFn),
		),
	)
}

// TestOTelAgentDogtelSecretsStandalone is the entry point for the secrets suite.
// It provisions a KindVM cluster and deploys the otel-agent as a standalone
// DaemonSet pre-configured with ENC[] secrets resolution.
func TestOTelAgentDogtelSecretsStandalone(t *testing.T) {
	t.Parallel()
	e2e.Run(t, &dogtelSecretsTestSuite{},
		e2e.WithProvisioner(dogtelSecretsStandaloneProvisioner()),
	)
}

func (s *dogtelSecretsTestSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	defer s.CleanupOnSetupFailure()
	utils.TestCalendarApp(s, false, utils.CalendarService)
}

// TestDogtelSecretsResolution verifies that secretsfx.Module() (the real secrets
// implementation) is active in standalone mode by confirming that an ENC[file@...]
// handle in DD_HOSTNAME is resolved to the actual value at agent startup.
//
// The K8s secret and all secrets configuration are set up in the provisioner
// (via WithK8sSecret and WithExtraEnvVars) so they are present when the agent
// pod starts — no UpdateEnv mid-test is required.
//
// The test config (dogtel-secrets.yml) uses allow_hostname_override: true on
// the infraattributes processor.  This causes the processor to inject
// "datadog.host.name" (from the agent's resolved hostname component) into span
// resource attributes.  That attribute takes priority over k8s.node.name in the
// trace-agent hostname detection, so tp.Hostname carries the value from
// DD_HOSTNAME after ENC[] resolution.  Without allow_hostname_override, k8s.node.name
// (added by infraattributes) would always win and the resolved DD_HOSTNAME would
// be invisible in traces, making it impossible to distinguish secrets-resolved from
// noop cases in a K8s environment.
func (s *dogtelSecretsTestSuite) TestDogtelSecretsResolution() {
	err := s.Env().FakeIntake.Client().FlushServerAndResetAggregators()
	require.NoError(s.T(), err)

	s.T().Logf("Waiting for traces with resolved hostname %q", dogtelResolvedHostname)
	require.EventuallyWithT(s.T(), func(c *assert.CollectT) {
		traces, err := s.Env().FakeIntake.Client().GetTraces()
		assert.NoError(c, err)
		assert.NotEmpty(c, traces)
		for _, trace := range traces {
			for _, tp := range trace.TracerPayloads {
				assert.Equal(c, dogtelResolvedHostname, tp.Hostname,
					"hostname should be the resolved ENC[] value, not the raw handle; "+
						"raw value would indicate secretsnoopfx is wired instead of secretsfx")
			}
		}
	}, 5*time.Minute, 10*time.Second)
}
