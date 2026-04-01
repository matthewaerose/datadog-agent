from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from invoke.exceptions import Exit

from tasks.libs.gpu.api import (
    discover_live_gpu_configs,
    fetch_metric_all_tags,
    list_observed_gpu_metrics_for_gpu_config,
    query_device_count,
    query_expected_metrics_presence_for_gpu_config,
)
from tasks.libs.gpu.types import (
    ArchitecturesSpec,
    GPUConfig,
    GPUConfigValidationResult,
    GPUConfigValidationState,
    Metric,
    MetricsSpec,
    TagsSpec,
    ValidationResults,
)

if TYPE_CHECKING:
    from datadog_api_client.v2.api.metrics_api import MetricsApi as MetricsApiV2
    from pydantic import BaseModel


SCALAR_QUERY_BATCH_SIZE = 50


def require_api_keys() -> None:
    if not os.environ.get("DD_API_KEY"):
        raise Exit("DD_API_KEY environment variable is required", code=1)
    if not os.environ.get("DD_APP_KEY"):
        raise Exit("DD_APP_KEY environment variable is required", code=1)


def resolve_spec_paths() -> tuple[str, str, str]:
    repo_root = Path(__file__).resolve().parents[3]
    base_spec_path = repo_root / "pkg" / "collector" / "corechecks" / "gpu" / "spec"
    spec_path = str(base_spec_path / "gpu_metrics.yaml")
    architectures_path = str(base_spec_path / "architectures.yaml")
    tags_path = str(base_spec_path / "tags.yaml")

    if not Path(spec_path).exists():
        raise Exit(f"Spec file not found: {spec_path}", code=1)
    if not Path(architectures_path).exists():
        raise Exit(f"Architectures file not found: {architectures_path}", code=1)
    if not Path(tags_path).exists():
        raise Exit(f"Tags file not found: {tags_path}", code=1)

    return spec_path, architectures_path, tags_path


ModelT = TypeVar("ModelT", bound=BaseModel)


def load_yaml_model(path: str, model_cls: type[ModelT]) -> ModelT:
    import yaml
    from pydantic import ValidationError

    with open(path) as f:
        raw = yaml.safe_load(f)
    try:
        return model_cls.model_validate(raw)
    except ValidationError as e:
        raise ValueError(f"Invalid schema in {path}:\n{e}") from e


def get_expected_metrics_for_gpu_config(spec_model: MetricsSpec, gpu_config: GPUConfig) -> dict[str, Metric]:
    expected: dict[str, Metric] = {}
    for metric_name, metric in spec_model.metrics.items():
        if metric.deprecated:
            continue
        if gpu_config.architecture in metric.support.unsupported_architectures:
            continue
        mode_support = metric.support.device_modes.get(gpu_config.device_mode)
        if not mode_support:
            continue
        expected[f"{spec_model.metric_prefix}.{metric_name}"] = metric
    return expected


def get_expected_tags_for_metric(tags_model: TagsSpec, metric: Metric) -> set[str]:
    tags: set[str] = set()
    for tagset_name in metric.tagsets:
        tagset = tags_model.tagsets.get(tagset_name)
        if tagset:
            tags.update(tagset.tags)
    tags.update(metric.custom_tags)
    return tags


def resolve_metric_tag_names(tags_model: TagsSpec, metric_name: str, metric: Metric) -> set[str]:
    tags: set[str] = set()
    for tagset_name in metric.tagsets:
        tagset = tags_model.tagsets.get(tagset_name)
        if tagset is None:
            raise ValueError(f"metric {metric_name} references unknown tagset {tagset_name}")
        for tag_name in tagset.tags:
            if tag_name not in tags_model.tags:
                raise ValueError(f"tagset {tagset_name} references unknown tag {tag_name}")
            tags.add(tag_name)
    for tag_name in metric.custom_tags:
        if tag_name not in tags_model.tags:
            raise ValueError(f"metric {metric_name} references unknown custom tag {tag_name}")
        tags.add(tag_name)
    return tags


def batch_items(items: list[str], chunk_size: int) -> list[list[str]]:
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def _build_expected_tags_by_metric(
    metrics_model: MetricsSpec, tags_model: TagsSpec, expected_metrics_map: dict[str, Metric]
) -> dict[str, set[str]]:
    expected_tags_by_metric: dict[str, set[str]] = {}
    for metric_name in expected_metrics_map:
        relative_name = metric_name.removeprefix(f"{metrics_model.metric_prefix}.")
        expected_tags_by_metric[metric_name] = get_expected_tags_for_metric(
            tags_model, metrics_model.metrics[relative_name]
        )
    return expected_tags_by_metric


def validate_metric_tags(
    api: MetricsApiV2,
    metric_name: str,
    tags_model: TagsSpec,
    expected_tags: set[str],
    tag_name_filter: str | None = None,
    window_seconds: int = 14400,
    metric_scope_filter: str | None = None,
) -> dict[str, list[str]]:
    validated_tags = {tag_name for tag_name in expected_tags if tags_model.tags[tag_name].regex}
    if tag_name_filter:
        validated_tags = {tag_name for tag_name in validated_tags if tag_name_filter in tag_name}
    if not validated_tags:
        return {}

    all_tags = fetch_metric_all_tags(
        api,
        metric_name,
        validated_tags,
        window_seconds=window_seconds,
        metric_scope_filter=metric_scope_filter or "",
    )
    invalid_values: dict[str, list[str]] = {}
    for tag_name in sorted(validated_tags):
        tag_spec = tags_model.tags[tag_name]
        if tag_spec.regex is None:
            continue
        pattern = re.compile(tag_spec.regex)
        mismatches = sorted({value for value in all_tags.get(tag_name, []) if not pattern.fullmatch(value)})
        if mismatches:
            invalid_values[tag_name] = mismatches
    return invalid_values


def compute_tag_validation(
    spec_path: str,
    tags_path: str,
    site: str,
    metric_name_filter: str | None = None,
    tag_name_filter: str | None = None,
    window_seconds: int = 14400,
    metric_scope_filter: str | None = None,
) -> tuple[dict[str, dict[str, list[str]]], list[str]]:
    from datadog_api_client import ApiClient, Configuration
    from datadog_api_client.v2.api.metrics_api import MetricsApi as MetricsApiV2

    from tasks.libs.gpu.types import MetricsSpec, TagsSpec

    spec_model = load_yaml_model(spec_path, MetricsSpec)
    tags_model = load_yaml_model(tags_path, TagsSpec)

    failures: dict[str, dict[str, list[str]]] = {}
    errors: list[str] = []
    config = Configuration()
    config.server_variables["site"] = site
    with ApiClient(config) as api_client:
        metrics_api_v2 = MetricsApiV2(api_client)
        for relative_metric_name, metric in sorted(spec_model.metrics.items()):
            metric_name = f"{spec_model.metric_prefix}.{relative_metric_name}"
            if metric_name_filter and metric_name_filter not in metric_name:
                continue
            try:
                expected_tags = resolve_metric_tag_names(tags_model, metric_name, metric)
                invalid_values = validate_metric_tags(
                    metrics_api_v2,
                    metric_name,
                    tags_model,
                    expected_tags,
                    tag_name_filter=tag_name_filter,
                    window_seconds=window_seconds,
                    metric_scope_filter=metric_scope_filter,
                )
            except Exception as e:
                errors.append(str(e))
                continue
            if invalid_values:
                failures[metric_name] = invalid_values
    return failures, errors


def determine_result_state(result: GPUConfigValidationResult) -> GPUConfigValidationState:
    if not result.config.is_known:
        return GPUConfigValidationState.UNKNOWN
    if result.missing_metrics or result.unknown_metrics or result.tag_failures:
        return GPUConfigValidationState.FAIL
    return GPUConfigValidationState.OK


def validate_gpu_config(
    metrics_api_v2: MetricsApiV2,
    metrics_model: MetricsSpec,
    tags_model: TagsSpec,
    gpu_config: GPUConfig,
    from_ts: int,
    to_ts: int,
    scalar_query_batch_size: int = SCALAR_QUERY_BATCH_SIZE,
) -> GPUConfigValidationResult:
    expected_metrics_map = get_expected_metrics_for_gpu_config(metrics_model, gpu_config)
    expected_metrics = list(expected_metrics_map.keys())
    device_count = query_device_count(metrics_api_v2, gpu_config, from_ts, to_ts)
    query_filter = gpu_config.to_tag_filter()

    result = GPUConfigValidationResult(
        config=gpu_config,
        device_count=device_count,
        expected_metrics=set(expected_metrics),
    )

    if device_count == 0:
        result.state = GPUConfigValidationState.MISSING
        return result

    expected_tags_by_metric = _build_expected_tags_by_metric(metrics_model, tags_model, expected_metrics_map)

    for metric_batch in batch_items(expected_metrics, scalar_query_batch_size):
        batch_present, batch_failures = query_expected_metrics_presence_for_gpu_config(
            metrics_api_v2,
            metric_batch,
            expected_tags_by_metric,
            query_filter,
            from_ts,
            to_ts,
        )
        result.present_metrics.update(batch_present)
        result.tag_failures.update(batch_failures)

    live_gpu_metrics = list_observed_gpu_metrics_for_gpu_config(
        metrics_api_v2,
        gpu_config,
        max(to_ts - from_ts, 0),
        metrics_model.metric_prefix,
    )
    result.unknown_metrics = live_gpu_metrics - set(expected_metrics)
    result.state = determine_result_state(result)
    return result


def combine_known_and_live_gpu_configs(
    known_gpu_configs: list[GPUConfig],
    live_gpu_config_keys: set[tuple[str, str]],
) -> list[GPUConfig]:
    by_key: dict[tuple[str, str], GPUConfig] = {(c.architecture, c.device_mode): c for c in known_gpu_configs}
    for key in sorted(live_gpu_config_keys):
        if key not in by_key:
            by_key[key] = GPUConfig(architecture=key[0], device_mode=key[1], is_known=False)
    return sorted(by_key.values(), key=lambda gpu_config: (gpu_config.architecture, gpu_config.device_mode))


def compute_validation(
    spec_path: str,
    architectures_path: str,
    site: str,
    lookback_seconds: int,
    progress_writer: Any | None = None,
) -> ValidationResults:
    from datadog_api_client import ApiClient, Configuration
    from datadog_api_client.v2.api.metrics_api import MetricsApi as MetricsApiV2

    metrics_model = load_yaml_model(spec_path, MetricsSpec)
    architectures_model = load_yaml_model(architectures_path, ArchitecturesSpec)
    tags_path = resolve_spec_paths()[2]
    tags_model = load_yaml_model(tags_path, TagsSpec)
    now = int(time.time())
    from_ts = now - int(lookback_seconds)
    known_gpu_configs = architectures_model.build_combinations()
    failing_count = 0

    config = Configuration()
    config.server_variables["site"] = site
    results: list[GPUConfigValidationResult] = []
    with ApiClient(config) as api_client:
        metrics_api_v2 = MetricsApiV2(api_client)
        live_gpu_config_keys = discover_live_gpu_configs(metrics_api_v2, from_ts, now)
        gpu_configs = combine_known_and_live_gpu_configs(known_gpu_configs, live_gpu_config_keys)

        if progress_writer is not None:
            progress_writer(f"Validating {len(gpu_configs)} GPU configs...")

        for gpu_config in gpu_configs:
            result = validate_gpu_config(
                metrics_api_v2,
                metrics_model,
                tags_model,
                gpu_config,
                from_ts,
                now,
                SCALAR_QUERY_BATCH_SIZE,
            )

            if not gpu_config.is_known and result.device_count == 0:
                continue

            results.append(result)

            if gpu_config.is_known and result.has_failures:
                failing_count += 1

    return ValidationResults(
        site=site,
        metrics_count=len(metrics_model.metrics),
        architectures_count=len(architectures_model.architectures),
        results=results,
        failing_count=failing_count,
    )
