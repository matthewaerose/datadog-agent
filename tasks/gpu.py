from __future__ import annotations

import csv
from pathlib import Path

# Run with:
# dda inv --dep "datadog-api-client>=2.52.0" --dep "pydantic>=2.0" --dep "pyyaml>=6.0" --dep "tabulate>=0.9.0"
from invoke import task
from invoke.exceptions import Exit

from tasks.libs.common.auth import dd_auth_api_app_keys


def _select_orgs(org: str | None) -> list[tuple[str, str]]:
    orgs_by_name = {
        "prod": ("prod", "app.datadoghq.com"),
        "staging": ("staging", "ddstaging.datadoghq.com"),
    }
    if org is not None:
        return [orgs_by_name[org]]
    return list(orgs_by_name.values())


@task(
    name="validate-metrics",
    help={
        "lookback_seconds": "Metrics lookback window in seconds",
        "org": "Datadog org filter: prod, staging. If not provided, use all configured orgs",
    },
)
def validate_metrics(ctx, lookback_seconds=3600, org: str | None = None):
    """
    Validate live GPU metrics for the selected Datadog org(s).
    """
    # Import here to avoid bringing in dependencies that are not always installed.
    from tasks.libs.gpu.render import render_results
    from tasks.libs.gpu.types import ValidationResults
    from tasks.libs.gpu.validation import Specs, compute_validation, require_api_keys

    specs = Specs.load()
    orgs = _select_orgs(org)

    results: ValidationResults | None = None
    org_errors: list[str] = []
    for org_name, dd_auth_domain in orgs:
        print(f"\n== Running GPU validation for {org_name} ({dd_auth_domain}) ==")
        try:
            with dd_auth_api_app_keys(ctx, dd_auth_domain):
                require_api_keys()
                result = compute_validation(
                    specs,
                    "datadoghq.com",
                    int(lookback_seconds),
                    progress_writer=print,
                )
                if results is None:
                    results = result
                else:
                    results.update(result)
        except Exception as e:
            org_errors.append(f"{org_name}: {e}")
            print(f"[ERROR] {org_name} failed: {e}")

    if results:
        render_results(results)

    if org_errors:
        print("\nOrg execution errors:")
        for err in org_errors:
            print(f"  - {err}")
        raise Exit(code=1)

    if results and results.failing_count > 0:
        raise Exit(code=1)


@task(
    name="validate-tags",
    help={
        "window_seconds": "All-tags lookup window in seconds (defaults to 14400 / 4 hours)",
        "org": "Datadog org filter: prod, staging. If not provided, use all configured orgs",
        "metric_name_filter": "Only validate metrics whose full name contains this substring",
        "tag_name_filter": "Only validate spec tag names containing this substring",
        "filter_tags": "Optional all-tags endpoint filter[tags] expression",
    },
)
def validate_tags(
    ctx,
    window_seconds=14400,
    org: str | None = None,
    metric_name_filter=None,
    tag_name_filter=None,
    filter_tags=None,
):
    """
    Validate GPU metric tag values against regexes from tags.yaml for the selected Datadog org(s).
    """
    from tasks.libs.gpu.render import render_tag_validation_results
    from tasks.libs.gpu.validation import Specs, compute_tag_validation, require_api_keys

    specs = Specs.load()
    orgs = _select_orgs(org)

    all_failures: dict[str, dict[str, list[str]]] = {}
    org_errors: list[str] = []
    for org_name, dd_auth_domain in orgs:
        print(f"\n== Running GPU tag validation for {org_name} ({dd_auth_domain}) ==")
        try:
            with dd_auth_api_app_keys(ctx, dd_auth_domain):
                require_api_keys()
                failures, errors = compute_tag_validation(
                    specs,
                    "datadoghq.com",
                    metric_name_filter=metric_name_filter,
                    tag_name_filter=tag_name_filter,
                    window_seconds=int(window_seconds),
                    metric_scope_filter=filter_tags or "",
                )
                for metric_name, tags_for_metric in failures.items():
                    target = all_failures.setdefault(metric_name, {})
                    for tag_name, values in tags_for_metric.items():
                        target[tag_name] = sorted(set(target.get(tag_name, [])) | set(values))
                org_errors.extend(f"{org_name}: {err}" for err in errors)
        except Exception as e:
            org_errors.append(f"{org_name}: {e}")
            print(f"[ERROR] {org_name} failed: {e}")

    render_tag_validation_results("datadoghq.com", all_failures, org_errors)
    if all_failures or org_errors:
        raise Exit(code=1)


DEFAULT_METRIC_TABLE_OUTPUT = "pkg/collector/corechecks/gpu/spec/metric_table.csv"


@task(
    name="generate-metric-table",
    help={
        "output": f"Output CSV path (defaults to {DEFAULT_METRIC_TABLE_OUTPUT})",
    },
)
def generate_metric_table(_, output: str = DEFAULT_METRIC_TABLE_OUTPUT):
    """
    Generate a CSV table with GPU metric metadata.
    """
    from tasks.libs.gpu.validation import Specs

    specs = Specs.load()
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    architecture_order = [name.lower() for name in specs.architectures.architectures]
    last_architecture = architecture_order[-1] if architecture_order else None
    fieldnames = [
        "Metric name",
        "Min/max supported architecture",
        "Tagset",
        "Extra tags",
        "MIG support",
        "vGPU support",
        "Aggregation type",
        "Time aggregation",
        "Group aggregation",
        "Granularity aggregation",
        "Granularity tags",
    ]
    rows_written = 0

    with open(output_path, "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for metric_name, metric in sorted(specs.metrics.metrics.items()):
            unsupported_architectures = {arch.lower() for arch in metric.support.unsupported_architectures}
            supported_architectures = [arch for arch in architecture_order if arch not in unsupported_architectures]
            if not supported_architectures:
                min_max_supported_architecture = "n/a"
            else:
                min_architecture = supported_architectures[0]
                max_architecture = supported_architectures[-1]
                if min_architecture == max_architecture or (
                    last_architecture and max_architecture == last_architecture
                ):
                    min_max_supported_architecture = min_architecture
                else:
                    min_max_supported_architecture = f"{min_architecture}-{max_architecture}"

            row = {
                "Metric name": f"{specs.metrics.metric_prefix}.{metric_name}",
                "Min/max supported architecture": min_max_supported_architecture,
                "Tagset": "|".join(metric.tagsets),
                "Extra tags": "|".join(metric.custom_tags),
                "MIG support": str(metric.support.device_modes.get("mig", False)).lower(),
                "vGPU support": str(metric.support.device_modes.get("vgpu", False)).lower(),
            }

            if metric.aggregation:
                row["Aggregation type"] = metric.aggregation.type

                if metric.aggregation.type in specs.aggregations.aggregations:
                    aggregation_details = specs.aggregations.aggregations[metric.aggregation.type]
                    row["Time aggregation"] = aggregation_details.time_aggregator
                    row["Group aggregation"] = aggregation_details.group_aggregator
                    row["Granularity aggregation"] = aggregation_details.granularity_aggregator

            granularity_tags = {"host", "gpu_uuid"}
            granularity_tags.update(metric.custom_tags)
            if "process" in metric.tagsets:
                granularity_tags.add("pid")

            writer.writerow(row)
            rows_written += 1

    print(f"Wrote {rows_written} rows to {output_path}")
