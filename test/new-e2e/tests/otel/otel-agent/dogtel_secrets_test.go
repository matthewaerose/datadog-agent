// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package otelagent contains e2e otel agent tests
package otelagent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/DataDog/datadog-agent/test/e2e-framework/components/datadog/kubernetesagentparams"
	scenkindvm "github.com/DataDog/datadog-agent/test/e2e-framework/scenarios/aws/kindvm"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/e2e"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/environments"
	provkindvm "github.com/DataDog/datadog-agent/test/e2e-framework/testing/provisioners/aws/kubernetes/kindvm"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/otel/utils"
)

const (
	dogtelSecretsNamespace = "datadog"
	dogtelSecretsName      = "dogtel-secrets"
	// dogtelResolvedHostname is the hostname value stored in the K8s secret.
	// If secretsfx.Module() is active the ENC[] handle resolves to this value;
	// the noop impl would leave the raw "ENC[file@...]" literal unchanged.
	dogtelResolvedHostname = "dogtel-secrets-test-host"
)

// dogtelSecretsTestSuite verifies that secretsfx.Module() (real secrets) is wired
// when DD_OTEL_STANDALONE=true by confirming ENC[] handle resolution end-to-end.
type dogtelSecretsTestSuite struct {
	e2e.BaseSuite[environments.Kubernetes]
}

// TestOTelAgentDogtelSecretsStandalone is the entry point for the secrets suite.
// It provisions a KindVM cluster in basic standalone mode (no secrets configured
// initially). The actual secrets test redeploys via UpdateEnv after creating the
// K8s secret, ensuring the secret exists before the agent starts.
func TestOTelAgentDogtelSecretsStandalone(t *testing.T) {
	values := dogtelStandaloneHelmValues
	t.Parallel()
	e2e.Run(t, &dogtelSecretsTestSuite{},
		e2e.WithProvisioner(provkindvm.Provisioner(
			provkindvm.WithRunOptions(
				scenkindvm.WithAgentOptions(
					kubernetesagentparams.WithHelmValues(values),
					kubernetesagentparams.WithOTelAgent(),
					kubernetesagentparams.WithOTelConfig(dogtelStandaloneConfig),
				),
			),
		)),
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
// Strategy:
//  1. Create a Kubernetes Secret containing a known hostname string.
//  2. Redeploy the otel-agent with DD_HOSTNAME=ENC[file@...] pointing at that
//     secret, plus DD_SECRET_BACKEND_COMMAND=/readsecret_multiple_providers.sh
//     (the built-in multi-provider script present in the agent image).
//  3. Confirm that traces arriving at the fake intake all report the known hostname,
//     proving the agent resolved the ENC[] handle rather than using the raw literal.
//     If the noop secrets impl were wired, the hostname would be the raw
//     "ENC[file@/etc/dogtel-secrets/hostname]" string instead.
func (s *dogtelSecretsTestSuite) TestDogtelSecretsResolution() {
	// 1. Create the Kubernetes secret before redeploying so it is present when the agent starts.
	s.applyDogtelSecret(dogtelSecretsNamespace, dogtelSecretsName, map[string][]byte{
		"hostname": []byte(dogtelResolvedHostname),
	})

	// 2. Redeploy otel-agent with secrets backend command, ENC[] hostname, and volume mount.
	// Start from the shared standalone values and layer the secrets-specific additions.
	// secretsValues layers the volume mount and extra env vars on top of the shared
	// standalone base values (dogtelStandaloneHelmValues).
	secretsValues := `
agents:
  volumes:
    - name: dogtel-secrets
      secret:
        secretName: dogtel-secrets
  containers:
    otelAgent:
      env:
        - name: DD_SECRET_BACKEND_COMMAND
          value: /readsecret_multiple_providers.sh
        - name: DD_HOSTNAME
          value: 'ENC[file@/etc/dogtel-secrets/hostname]'
      volumeMounts:
        - name: dogtel-secrets
          mountPath: /etc/dogtel-secrets
`
	s.UpdateEnv(provkindvm.Provisioner(
		provkindvm.WithRunOptions(
			scenkindvm.WithAgentOptions(
				kubernetesagentparams.WithHelmValues(dogtelStandaloneHelmValues),
				kubernetesagentparams.WithHelmValues(secretsValues),
				kubernetesagentparams.WithOTelAgent(),
				kubernetesagentparams.WithOTelConfig(dogtelStandaloneConfig),
			),
		),
	))

	err := s.Env().FakeIntake.Client().FlushServerAndResetAggregators()
	require.NoError(s.T(), err)

	// 3. Verify traces arrive with the resolved hostname, not the raw ENC[] literal.
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

// applyDogtelSecret creates or updates a Kubernetes secret in the given namespace.
func (s *dogtelSecretsTestSuite) applyDogtelSecret(namespace, name string, data map[string][]byte) {
	client := s.Env().KubernetesCluster.KubernetesClient.K8sClient
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	_, err := client.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		_, err = client.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	} else {
		_, err = client.CoreV1().Secrets(namespace).Update(context.Background(), secret, metav1.UpdateOptions{})
	}
	require.NoError(s.T(), err, "failed to create/update K8s secret %s/%s", namespace, name)
}
