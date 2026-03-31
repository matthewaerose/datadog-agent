# Spot Scheduling E2E Tests

Integration tests for the cluster-agent spot scheduler using a local kind cluster.

## What's tested

- Spot/on-demand pod placement via the admission webhook
- `minOnDemand` constraint enforcement
- Fallback to on-demand when the spot node is unavailable
- Rebalancing after deployment scale-down

## Prerequisites

1. **Docker** and **kind** installed locally
2. A locally-built cluster-agent image

## Build the cluster-agent image

The cluster-agent must be built for Linux inside a devenv container (macOS binaries won't run in kind):

```bash
./build-cluster-agent-image.sh [image] [arch]
# defaults: image=${USER}/cluster-agent:test  arch=arm64
```

This produces `${USER}/cluster-agent:test` in the local Docker daemon.

## Run the tests

Run from the **repo root**. The test creates the kind cluster automatically and loads the image into it.

```bash
DD_TEST_CLUSTER_AGENT_IMAGE=${USER}/cluster-agent:test \
  PULUMI_CONFIG_PASSPHRASE=dummy \
  dda inv new-e2e-tests.run --targets=./tests/autoscaling/spot/... \
  -e "-test.timeout 10m"
```

If `DD_TEST_CLUSTER_AGENT_IMAGE` is not set, tests are skipped.

## How it works

1. `localkubernetes.Provisioner` creates a 3-node kind cluster via Pulumi:
   - 1 control-plane node
   - 1 worker labeled `karpenter.sh/capacity-type=on-demand`
   - 1 worker labeled `karpenter.sh/capacity-type=spot` with a `NoSchedule` taint
2. The cluster-agent image is loaded into kind via `WithKindLoadImage`.
3. The cluster-agent is deployed via Helm with spot scheduling enabled and short timeouts.
4. Tests create Deployments, observe pod placement via the k8s API, and verify spot/on-demand ratios.

## Configuration

The following env vars and timeouts are set in `spotHelmValues`:

| Config | Value | Purpose |
|--------|-------|---------|
| `DD_AUTOSCALING_CLUSTER_SPOT_SCHEDULE_TIMEOUT` | 30s | Fallback trigger speed; 30s gives the poller time to observe pending spot pods |
| `DD_AUTOSCALING_CLUSTER_SPOT_FALLBACK_DURATION` | 60s | How long fallback lasts (2× schedule timeout, ensuring the test can uncordon the spot node before fallback expires) |
| `DD_AUTOSCALING_CLUSTER_SPOT_REBALANCE_STABILIZATION_PERIOD` | 10s | Rebalancing speed |

Short timeouts make fallback and rebalancing tests complete in under a minute.
The schedule timeout is intentionally 30s (not shorter) to avoid a race between
the poller observing pending spot pods and the scheduler triggering fallback.

## Iterating

Use `e2e.WithDevMode()` to keep the kind cluster alive after test failures so you can
inspect pod state directly:

```bash
DD_TEST_CLUSTER_AGENT_IMAGE=${USER}/cluster-agent:test \
  PULUMI_CONFIG_PASSPHRASE=dummy \
  E2E_DEV_MODE=true \
  dda inv new-e2e-tests.run --targets=./tests/autoscaling/spot/...
```

After inspecting, destroy the stack — this deletes the kind cluster and removes all Pulumi state:

```bash
# 1. Find the workspace for the spot scheduling stack
$TMPDIR/pulumi-workspace/*/*spotschedulingsuite*

# 2. Destroy resources (deletes the kind cluster) and remove the stack
PULUMI_CONFIG_PASSPHRASE=dummy pulumi destroy --cwd <workspace> --yes
PULUMI_CONFIG_PASSPHRASE=dummy pulumi stack rm  --cwd <workspace> --yes
```

## Known issues

### 1. Deployment deletion leaves stale tracker state

When a deployment is deleted, `onDeleted` removes its key from the workload config store. Subsequent WLM Unset events for the deployment's pods are then rejected by `spotEligibleFilter` (config key gone), so `tracker.deleted` is never called. The tracker permanently retains the stale spot/on-demand UIDs for those pods.
