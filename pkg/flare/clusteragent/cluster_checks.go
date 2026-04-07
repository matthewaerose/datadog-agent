// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package clusteragent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery/providers/names"
	ipc "github.com/DataDog/datadog-agent/comp/core/ipc/def"
	ipchttp "github.com/DataDog/datadog-agent/comp/core/ipc/httphelpers"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
	checkid "github.com/DataDog/datadog-agent/pkg/collector/check/id"
	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/flare"
)

// GetClusterChecks dumps the clustercheck dispatching state to the writer
func GetClusterChecks(w io.Writer, checkName string, c ipc.HTTPClient) error {
	urlstr := fmt.Sprintf("https://localhost:%v/api/v1/clusterchecks", pkgconfigsetup.Datadog().GetInt("cluster_agent.cmd_port"))
	urlValues := url.Values{}
	urlValues.Set("scrub", "true")

	if w != color.Output {
		color.NoColor = true
	}

	if !pkgconfigsetup.Datadog().GetBool("cluster_checks.enabled") {
		fmt.Fprintln(w, "Cluster-checks are not enabled")
		return nil
	}

	r, err := c.Get(urlstr, ipchttp.WithLeaveConnectionOpen, ipchttp.WithValues(urlValues))
	if err != nil {
		if r != nil && string(r) != "" {
			fmt.Fprintf(w, "The agent ran into an error while checking config: %s\n", string(r))
		} else {
			fmt.Fprintf(w, "Failed to query the agent (running?): %s\n", err)
		}
		return err
	}

	var cr types.StateResponse
	err = json.Unmarshal(r, &cr)
	if err != nil {
		return err
	}

	// Gracefully exit when dispatcher is not running
	if len(cr.NotRunning) > 0 {
		fmt.Fprintf(w, "Cluster-check dispatching logic not running: %s\n", cr.NotRunning)
		return nil
	}

	// Print warmup message
	if cr.Warmup {
		fmt.Fprintf(w, "=== %s in progress ===\n", color.BlueString("Warmup"))
		fmt.Fprintln(w, "No configuration has been processed yet")
		fmt.Fprintln(w, "")
	}

	// Print dangling configs
	if len(cr.Dangling) > 0 {
		fmt.Fprintf(w, "=== %s configurations ===\n", color.RedString("Unassigned"))
		for _, c := range cr.Dangling {
			flare.PrintClusterCheckConfig(w, c, checkName)
		}
		fmt.Fprintln(w, "")
	}

	// Print summary of agents
	if len(cr.Nodes) == 0 {
		fmt.Fprintf(w, "=== %s agent reporting ===\n", color.RedString("Zero"))
		fmt.Fprintln(w, "No check will be dispatched until agents report to the cluster-agent")
		return nil
	}
	fmt.Fprintf(w, "=== %d agents reporting ===\n", len(cr.Nodes))
	sort.Slice(cr.Nodes, func(i, j int) bool { return cr.Nodes[i].Name < cr.Nodes[j].Name })
	table := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	fmt.Fprintln(table, "\nName\tRunning checks")
	for _, n := range cr.Nodes {
		fmt.Fprintf(table, "%s\t%d\n", n.Name, len(n.Configs))
	}
	table.Flush()

	// Print per-node configurations with execution status
	for _, node := range cr.Nodes {
		if len(node.Configs) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n===== Checks on %s =====\n", color.HiMagentaString(node.Name))
		for _, c := range node.Configs {
			flare.PrintClusterCheckConfig(w, c, checkName)
			printCheckExecutionStatus(w, c, node.Stats, checkName)
		}
	}

	return nil
}

// printCheckExecutionStatus prints the execution status for each instance of a config,
// matching the node agent `agent status collector` output format.
func printCheckExecutionStatus(w io.Writer, c integration.Config, stats types.CLCRunnersStats, checkName string) {
	if checkName != "" && c.Name != checkName {
		return
	}
	if len(stats) == 0 {
		return
	}

	configDigest := c.FastDigest()
	for _, inst := range c.Instances {
		id := string(checkid.BuildID(c.Name, configDigest, inst, c.InitConfig))
		s, found := stats[id]
		if !found {
			// Check IDs can differ between DCA and runner due to secret decryption.
			// Fall back to matching by check name prefix.
			for statsID, statEntry := range stats {
				if strings.HasPrefix(statsID, c.Name+":") {
					s = statEntry
					found = true
					id = statsID
					break
				}
			}
			if !found {
				continue
			}
		}

		// Status indicator
		statusStr := color.GreenString("OK")
		if s.LastExecFailed {
			statusStr = color.RedString("ERROR")
		}
		fmt.Fprintf(w, "  Instance ID: %s [%s]\n", id, statusStr)

		// Run counts
		fmt.Fprintf(w, "  Total Runs: %d\n", s.TotalRuns)

		// Metric samples
		fmt.Fprintf(w, "  Metric Samples: Last Run: %d, Total: %d\n", s.MetricSamples, s.TotalMetricSamples)

		// Events
		fmt.Fprintf(w, "  Events: Last Run: %d, Total: %d\n", s.Events, s.TotalEvents)

		// Service checks
		fmt.Fprintf(w, "  Service Checks: Last Run: %d, Total: %d\n", s.ServiceChecks, s.TotalServiceChecks)

		// Average execution time
		fmt.Fprintf(w, "  Average Execution Time : %s\n", formatExecutionTime(s.AverageExecutionTime))

		// Last execution date
		if s.LastExecutionDate > 0 {
			t := time.UnixMilli(s.LastExecutionDate).UTC()
			fmt.Fprintf(w, "  Last Execution Date : %s\n", t.Format("2006-01-02 15:04:05 MST"))
		}

		// Last successful execution date
		if s.LastSuccessDate > 0 {
			t := time.Unix(s.LastSuccessDate, 0).UTC()
			fmt.Fprintf(w, "  Last Successful Execution Date : %s\n", t.Format("2006-01-02 15:04:05 MST"))
		}

		// Last error
		if s.LastError != "" {
			fmt.Fprintf(w, "  %s: %s\n", color.RedString("Last Error"), s.LastError)
		}

		fmt.Fprintln(w, "")
	}
}

// formatExecutionTime formats milliseconds into a human-readable duration string
func formatExecutionTime(ms int) string {
	if ms == 0 {
		return "0s"
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.3fs", float64(ms)/1000.0)
}

// GetEndpointsChecks dumps the endpointschecks dispatching state to the writer
func GetEndpointsChecks(w io.Writer, checkName string, c ipc.HTTPClient) error {
	if !endpointschecksEnabled() {
		return nil
	}

	urlstr := fmt.Sprintf("https://localhost:%v/api/v1/endpointschecks/configs", pkgconfigsetup.Datadog().GetInt("cluster_agent.cmd_port"))

	if w != color.Output {
		color.NoColor = true
	}

	// Query the cluster agent API
	r, err := c.Get(urlstr, ipchttp.WithLeaveConnectionOpen)
	if err != nil {
		if r != nil && string(r) != "" {
			fmt.Fprintf(w, "The agent ran into an error while checking config: %s\n", string(r))
		} else {
			fmt.Fprintf(w, "Failed to query the agent (running?): %s\n", err)
		}
		return err
	}

	var cr types.ConfigResponse
	if err = json.Unmarshal(r, &cr); err != nil {
		return err
	}

	// Print summary of pod-backed endpointschecks
	fmt.Fprintf(w, "\n===== %d Pod-backed Endpoints-Checks scheduled =====\n", len(cr.Configs))
	for _, c := range cr.Configs {
		flare.PrintClusterCheckConfig(w, c, checkName)
	}

	return nil
}

func endpointschecksEnabled() bool {
	return slices.Contains(pkgconfigsetup.Datadog().GetStringSlice("extra_config_providers"), names.KubeEndpointsRegisterName)
}
