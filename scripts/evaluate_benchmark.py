#!/usr/bin/env python3
"""Fail-closed conformance scorer for profiler benchmark comparisons."""

from __future__ import annotations

import json
import hashlib
import math
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
POLICY_BOOTSTRAP_MAXIMUM_BYTES = 1_048_576
METRICS = ("precision", "recall", "coverage", "latency", "bytesRead", "modelUsage", "calibration")
HIGHER_IS_BETTER = {"precision", "recall", "coverage"}
LOWER_IS_BETTER = {"latency", "bytesRead", "modelUsage", "calibration"}


def maximum_validation_artifact_bytes() -> int:
    policy_path = ROOT / "config" / "reference-policy.yaml"
    if policy_path.stat().st_size > POLICY_BOOTSTRAP_MAXIMUM_BYTES:
        raise ValueError(f"reference policy exceeds {POLICY_BOOTSTRAP_MAXIMUM_BYTES} bytes: {policy_path}")
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    maximum = policy.get("validation", {}).get("maximumArtifactBytes") if isinstance(policy, dict) else None
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum <= 0:
        raise ValueError("reference policy validation.maximumArtifactBytes must be a positive integer")
    return maximum


def load(path: Path):
    maximum = maximum_validation_artifact_bytes()
    if path.stat().st_size > maximum:
        raise ValueError(f"validation artifact exceeds {maximum} bytes: {path}")
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant {value!r}")

    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject_constant)


def validate(instance, schema_name: str) -> list[str]:
    schemas = [load(path) for path in (ROOT / "contracts").glob("*.schema.json")]
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas if "$id" in schema]
    )
    schema = next(schema for schema in schemas if schema["$id"].endswith(f"/{schema_name}"))
    return [error.message for error in Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).iter_errors(instance)]


def resolve_pointer(document, pointer: str):
    value = document
    for token in pointer.lstrip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if re.fullmatch(r"0|[1-9][0-9]*", token) is None:
                raise ValueError(f"noncanonical JSON Pointer list index {token!r}")
            index = int(token)
            if index >= len(value):
                raise IndexError(f"JSON Pointer list index {index} is out of bounds")
            value = value[index]
        else:
            value = value[token]
    return value


def score(corpus: dict, comparison: dict, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if corpus.get("corpusVersion") != comparison.get("corpusVersion"):
        errors.append("corpus version mismatch")
    cases = corpus.get("cases", [])
    case_ids = [case.get("caseId") for case in cases]
    if len(case_ids) != len(set(case_ids)):
        errors.append("duplicate corpus case IDs")
    results = comparison.get("caseResults", [])
    result_ids = [row.get("caseId") for row in results]
    if len(result_ids) != len(set(result_ids)):
        errors.append("duplicate comparison case IDs")
    if set(result_ids) != set(case_ids):
        errors.append("comparison case inventory differs from corpus")
    expected_by_id = {case["caseId"]: case for case in cases}
    for case in cases:
        fixture_ref = case.get("fixtureRef", "")
        fixture_path = (root / fixture_ref.removeprefix("package://")).resolve() if fixture_ref.startswith("package://") else None
        if fixture_path is None or not fixture_path.is_file() or root.resolve() not in fixture_path.parents:
            errors.append(f"{case.get('caseId')}: fixture does not resolve inside the package")
            continue
        if hashlib.sha256(fixture_path.read_bytes()).hexdigest() != case.get("fixtureSha256"):
            errors.append(f"{case.get('caseId')}: fixture hash mismatch")
            continue
        try:
            fixture = load(fixture_path)
            probe = case.get("probe", {})
            observed = resolve_pointer(fixture, probe.get("pointer", ""))
            if observed is None or observed == "" or observed == [] or observed == {}:
                errors.append(f"{case.get('caseId')}: fixture probe returned empty")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{case.get('caseId')}: fixture probe failed: {exc}")
    for row in results:
        case = expected_by_id.get(row.get("caseId"))
        if case is None:
            continue
        if row.get("expectedOutcome") != case.get("expectedOutcome"):
            errors.append(f"{row.get('caseId')}: expected outcome differs from corpus")
        for label in ("baseline", "candidate"):
            execution = row.get(f"{label}Execution", {})
            agreement = execution.get("observedOutcome") == case.get("expectedOutcome")
            if execution.get("agreement") is not agreement:
                errors.append(f"{row.get('caseId')}: {label} agreement flag is not derived from outcomes")
            if not agreement:
                errors.append(f"{row.get('caseId')}: {label} observed outcome disagrees with corpus")
            if execution.get("executed", 0) <= 0 or execution.get("failed", 0) or execution.get("skipped", 0) or execution.get("notRun", 0):
                errors.append(f"{row.get('caseId')}: {label} benchmark case did not fully execute")
        if set(row.get("slices", [])) != set(case.get("slices", [])):
            errors.append(f"{row.get('caseId')}: slice labels differ from corpus")
    required_slices = set(corpus.get("requiredSlices", []))
    observed_slices = {value for row in results for value in row.get("slices", [])}
    if observed_slices != required_slices:
        errors.append("comparison does not cover every required difficult slice")

    baseline = comparison.get("baseline", {})
    candidate = comparison.get("candidate", {})
    def verify_metric(owner: str, metric: str, row: dict) -> float | None:
        numerator = row.get("numerator")
        denominator = row.get("denominator")
        value = row.get("value")
        if not all(isinstance(item, (int, float)) and not isinstance(item, bool) for item in (numerator, denominator, value)):
            errors.append(f"{owner} {metric} is unavailable")
            return None
        if not all(math.isfinite(item) for item in (numerator, denominator, value)):
            errors.append(f"{owner} {metric} must contain only finite numeric values")
            return None
        if denominator <= 0:
            errors.append(f"{owner} {metric} is unavailable")
            return None
        if numerator < 0 or value < 0:
            errors.append(f"{owner} {metric} contains a negative numerator or value")
        if metric in {"precision", "recall", "coverage", "calibration"} and (numerator > denominator or value > 1):
            errors.append(f"{owner} {metric} ratio is outside 0..1 or numerator exceeds denominator")
        derived = numerator / denominator
        if not math.isclose(value, derived, rel_tol=1e-12, abs_tol=1e-12):
            errors.append(f"{owner} {metric} value does not equal numerator divided by denominator")
        return derived

    for metric in METRICS:
        for label, measurement in (("baseline", baseline), ("candidate", candidate)):
            verify_metric(label, metric, measurement.get(metric, {}))
        for label, aggregate in (("baseline", baseline), ("candidate", candidate)):
            contributions = [row.get("metricContributions", {}).get(label, {}).get(metric, {}) for row in results]
            contribution_values = [verify_metric(f"case {row.get('caseId')} {label}", metric, contribution) for row, contribution in zip(results, contributions)]
            if all(value is not None for value in contribution_values):
                numerator = sum(row.get("numerator", 0) for row in contributions)
                denominator = sum(row.get("denominator", 0) for row in contributions)
                aggregate_metric = aggregate.get(metric, {})
                if not math.isclose(aggregate_metric.get("numerator", math.nan), numerator, rel_tol=1e-12, abs_tol=1e-12) or not math.isclose(aggregate_metric.get("denominator", math.nan), denominator, rel_tol=1e-12, abs_tol=1e-12):
                    errors.append(f"{label} {metric} aggregate does not reconcile to per-case contributions")
    maximum_regression = comparison.get("acceptance", {}).get("maximumCorrectnessRegression", 0)
    if not isinstance(maximum_regression, (int, float)) or isinstance(maximum_regression, bool) or not math.isfinite(maximum_regression):
        errors.append("maximumCorrectnessRegression must be finite")
        maximum_regression = 0
    for metric in HIGHER_IS_BETTER:
        before = baseline.get(metric, {}).get("value")
        after = candidate.get(metric, {}).get("value")
        if isinstance(before, (int, float)) and isinstance(after, (int, float)) and after < before - maximum_regression:
            errors.append(f"candidate {metric} regresses beyond the accepted bound")
    calibration_bound = comparison.get("acceptance", {}).get("maximumCalibrationRegression", 0)
    if not isinstance(calibration_bound, (int, float)) or isinstance(calibration_bound, bool) or not math.isfinite(calibration_bound):
        errors.append("maximumCalibrationRegression must be finite")
        calibration_bound = 0
    before_calibration = baseline.get("calibration", {}).get("value")
    after_calibration = candidate.get("calibration", {}).get("value")
    if isinstance(before_calibration, (int, float)) and isinstance(after_calibration, (int, float)) and after_calibration > before_calibration + calibration_bound:
        errors.append("candidate calibration regresses beyond the accepted bound")
    target = comparison.get("acceptance", {}).get("targetMetric")
    before_target = baseline.get(target, {}).get("value") if target in METRICS else None
    after_target = candidate.get(target, {}).get("value") if target in METRICS else None
    if target in HIGHER_IS_BETTER and not (isinstance(before_target, (int, float)) and isinstance(after_target, (int, float)) and after_target > before_target):
        errors.append("target metric did not improve")
    if target in LOWER_IS_BETTER and not (isinstance(before_target, (int, float)) and isinstance(after_target, (int, float)) and after_target < before_target):
        errors.append("target metric did not improve")
    derived_decision = "FAIL" if errors else "PASS"
    if comparison.get("acceptance", {}).get("decision") != derived_decision:
        errors.append("declared decision differs from scorer result")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("FAIL BENCHMARK: expected corpus and comparison paths")
        return 1
    try:
        corpus = load((ROOT / argv[1]).resolve() if not Path(argv[1]).is_absolute() else Path(argv[1]))
        comparison = load((ROOT / argv[2]).resolve() if not Path(argv[2]).is_absolute() else Path(argv[2]))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL BENCHMARK: input parse failed: {exc}")
        return 1
    errors = validate(corpus, "benchmark-corpus.schema.json")
    errors.extend(validate(comparison, "benchmark-comparison.schema.json"))
    errors.extend(score(corpus, comparison))
    if errors:
        print(f"FAIL BENCHMARK: {len(errors)} failure(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"PASS BENCHMARK: {len(comparison['caseResults'])} cases; 7 before/after metrics; 9 required slices")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
