// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package otelagent contains e2e otel agent tests
package otelagent

import (
	_ "embed"
	"testing"

	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	"github.com/DataDog/datadog-agent/test/e2e-framework/components/datadog/kubernetesagentparams"
	scenkindvm "github.com/DataDog/datadog-agent/test/e2e-framework/scenarios/aws/kindvm"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/e2e"
	"github.com/DataDog/datadog-agent/test/e2e-framework/testing/environments"
	provkindvm "github.com/DataDog/datadog-agent/test/e2e-framework/testing/provisioners/aws/kubernetes/kindvm"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/otel/utils"
)

//go:embed config/dogtel-standalone.yml
var dogtelStandaloneConfig string

// dogtelStandaloneHelmValues is the base Helm values block used by every dogtel
// standalone test suite. It enables the otel-agent (DD_OTEL_STANDALONE=true) and
// disables the core agent's competing data-collection features so the otel-agent
// is the sole telemetry source.
//
// Note: the Datadog Helm chart unconditionally includes the core agent container
// in the DaemonSet pod — it cannot be removed via chart values. Disabling the
// features below is the correct way to achieve a "standalone otel-agent only"
// deployment until a future chart version supports omitting the core agent.
const dogtelStandaloneHelmValues = `
datadog:
  otelCollector:
    useStandaloneImage: false
  # Disable core agent collection features – otel-agent handles all telemetry.
  apm:
    portEnabled: false
    socketEnabled: false
    instrumentation:
      enabled: false
  logs:
    enabled: false
    containerCollectAll: false
    containerCollectUsingFiles: false
  processAgent:
    processCollection: false
    containerCollection: false
  helmCheck:
    enabled: false
  kubeStateMetricsCore:
    enabled: false
agents:
  containers:
    otelAgent:
      env:
        - name: DD_OTEL_STANDALONE
          value: 'true'
`

// dogtelStandaloneTestSuite tests the dogtelextension running in standalone mode
// (DD_OTEL_STANDALONE=true). In this mode the extension starts its own workloadmeta
// store, tagger, and tagger gRPC server, providing Kubernetes infrastructure
// attribute enrichment independently of a co-located core Datadog Agent.
type dogtelStandaloneTestSuite struct {
	e2e.BaseSuite[environments.Kubernetes]
}

// TestOTelAgentDogtelExtensionStandalone is the entry point for the suite.
// It provisions a KindVM cluster with the otel-agent sidecar, enables standalone
// mode via DD_OTEL_STANDALONE=true, and loads the dogtel-standalone OTel config
// which includes the dogtelextension with a tagger gRPC server on port 15555.
func TestOTelAgentDogtelExtensionStandalone(t *testing.T) {
	values := dogtelStandaloneHelmValues
	t.Parallel()
	e2e.Run(t, &dogtelStandaloneTestSuite{},
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

var dogtelParams = utils.IAParams{
	InfraAttributes: true,
	EKS:             false,
	Cardinality:     types.LowCardinality,
}

func (s *dogtelStandaloneTestSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()
	defer s.CleanupOnSetupFailure()
	utils.TestCalendarApp(s, false, utils.CalendarService)
}

// TestDogtelAgentInstalled checks the otel-agent pod is running with the dogtelextension.
func (s *dogtelStandaloneTestSuite) TestDogtelAgentInstalled() {
	utils.TestOTelAgentInstalled(s)
}

// TestDogtelLivenessMetric verifies that the extension reports itself running by
// emitting otel.dogtel_extension.running (value=1) to the Datadog metrics endpoint.
// This metric is sent in Start() after the tagger server starts successfully,
// confirming both the extension lifecycle and the serializer pipeline work end-to-end.
func (s *dogtelStandaloneTestSuite) TestDogtelLivenessMetric() {
	utils.TestDogtelLivenessMetric(s)
}

// TestDogtelTaggerServerRunning confirms the tagger gRPC server is bound to
// port 15555 inside the otel-agent container, as configured in dogtel-standalone.yml.
// The server is started by dogtelextension.startTaggerServer() and exposes the
// workloadmeta-backed tagger to remote clients over mTLS.
func (s *dogtelStandaloneTestSuite) TestDogtelTaggerServerRunning() {
	utils.TestDogtelTaggerServerRunning(s, 15555)
}

// TestDogtelOTLPTraces verifies OTLP traces are enriched with Kubernetes workloadmeta
// tags (kube_deployment, pod_name, kube_namespace, etc.) via the infraattributes processor.
// In standalone mode these tags come from the tagger started by dogtelextension, which
// subscribes to the local workloadmeta store that watches the Kubernetes API.
func (s *dogtelStandaloneTestSuite) TestDogtelOTLPTraces() {
	utils.TestTraces(s, dogtelParams)
}

// TestDogtelOTLPMetrics verifies OTLP metrics carry Kubernetes workloadmeta tags.
func (s *dogtelStandaloneTestSuite) TestDogtelOTLPMetrics() {
	utils.TestMetrics(s, dogtelParams)
}

// TestDogtelOTLPLogs verifies OTLP logs carry Kubernetes workloadmeta tags.
func (s *dogtelStandaloneTestSuite) TestDogtelOTLPLogs() {
	utils.TestLogs(s, dogtelParams)
}

// TestDogtelHosts verifies that traces, metrics, and logs all report the same
// hostname, which in standalone mode is resolved by dogtelextension's hostname
// component (backed by the k8s node name from workloadmeta).
func (s *dogtelStandaloneTestSuite) TestDogtelHosts() {
	utils.TestHosts(s)
}
