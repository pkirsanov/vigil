#!/usr/bin/env python3
"""Fail-closed validator for the Agent Data Profiler Kit.

Uses pinned standards libraries plus deterministic semantic checks. It validates
the package inventory, JSON Schema and OpenAPI contracts, examples, evidence
integrity, cross-contract references, Gherkin syntax and traceability, relative
links, placeholders, and source/vendor sanitization.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import base64
import hashlib
import hmac
import ipaddress
import math
import re
import sys
import unicodedata
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
CONTROL_PATH = SCRIPT_DIR / "validation_control.py"
ROOT = Path(__file__).resolve().parents[1]
TRUST_REGISTRY_PATH: Path | None = None
TRUST_REGISTRY_SHA256: str | None = None
VALIDATION_CONTROL_SHA256: str | None = None
VALIDATION_VERIFIER_SHA256: str | None = None
REQUIRE_EXTERNAL_TRUST = False
_CONTROL_MODULE: Any | None = None


def load_validation_verifier(expected_sha256: str | None = None, require_external: bool = False):
    """Hash the verifier with stdlib code before executing any verifier bytes."""
    global _CONTROL_MODULE
    if require_external and expected_sha256 is None:
        raise ValueError("production trust requires an external validation-verifier SHA-256 pin")
    actual_sha256 = hashlib.sha256(CONTROL_PATH.read_bytes()).hexdigest()
    if expected_sha256 is not None and actual_sha256 != expected_sha256.lower():
        raise ValueError("validation verifier SHA-256 does not match the external pin")
    if _CONTROL_MODULE is None:
        spec = importlib.util.spec_from_file_location(
            "agent_data_profiler_validation_control", CONTROL_PATH
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load package-local validation control from {CONTROL_PATH}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CONTROL_MODULE = module
    return _CONTROL_MODULE


def load_trusted_issuers(*args, **kwargs):
    verifier = load_validation_verifier(VALIDATION_VERIFIER_SHA256, REQUIRE_EXTERNAL_TRUST)
    return verifier.load_trusted_issuers(*args, **kwargs)


def load_verified_control(*args, **kwargs):
    verifier = load_validation_verifier(VALIDATION_VERIFIER_SHA256, REQUIRE_EXTERNAL_TRUST)
    return verifier.load_verified_control(*args, **kwargs)

EXPECTED_ARTIFACTS = [
    "README.md",
    "package.yaml",
    "docs/00-executive-overview.md",
    "docs/01-product-requirements.md",
    "docs/02-reference-architecture.md",
    "docs/03-pipeline-and-algorithms.md",
    "docs/04-evidence-and-business-model.md",
    "docs/05-agent-consumption.md",
    "docs/06-lessons-gotchas-and-tuning.md",
    "docs/07-security-governance-and-privacy.md",
    "docs/08-operations-observability-and-slos.md",
    "docs/09-implementation-roadmap.md",
    "docs/10-evaluation-and-acceptance.md",
    "requirements/catalog.json",
    "requirements/catalog.schema.json",
    "pipeline/stages.json",
    "pipeline/capability-matrix.json",
    "pipeline/index-registry.json",
    "pipeline/source-kind-profiles.json",
    "contracts/source-descriptor.schema.json",
    "contracts/source-registration-request.schema.json",
    "contracts/source-boundary.schema.json",
    "contracts/source-structure.schema.json",
    "contracts/agent-response-policy.schema.json",
    "contracts/projection-safety-receipt.schema.json",
    "contracts/source-value-fingerprint-set.schema.json",
    "contracts/benchmark-corpus.schema.json",
    "contracts/benchmark-comparison.schema.json",
    "contracts/work-progress-page.schema.json",
    "contracts/work-progress-manifest.schema.json",
    "contracts/evidence-response.schema.json",
    "contracts/execution-budget-bundle.schema.json",
    "contracts/deletion-inventory-page.schema.json",
    "contracts/deletion-inventory-manifest.schema.json",
    "contracts/stage-receipt-bundle.schema.json",
    "contracts/stage-output-details.schema.json",
    "contracts/cross-scope-authorization-receipt.schema.json",
    "contracts/projection-coordinate.schema.json",
    "contracts/publication-receipt.schema.json",
    "contracts/storage-transition-receipt.schema.json",
    "contracts/cancellation-receipt.schema.json",
    "contracts/feedback-receipt.schema.json",
    "contracts/read-execution-result.schema.json",
    "contracts/retrieval-bundle.schema.json",
    "contracts/redaction-receipt.schema.json",
    "contracts/evidence-record.schema.json",
    "contracts/evidence-bundle.schema.json",
    "contracts/relationship-validation.schema.json",
    "contracts/profiling-run.schema.json",
    "contracts/profile-manifest.schema.json",
    "contracts/capability-manifest.schema.json",
    "contracts/business-model.schema.json",
    "contracts/read-plan.schema.json",
    "contracts/index-manifest.schema.json",
    "contracts/deletion-receipt.schema.json",
    "contracts/source-profile-extension.schema.json",
    "contracts/connector-metrics-extension.schema.json",
    "contracts/prompt-contracts.schema.json",
    "contracts/audit-event.schema.json",
    "contracts/model-execution.schema.json",
    "contracts/parser-execution.schema.json",
    "contracts/read-plan-validation-receipt.schema.json",
    "contracts/api.openapi.yaml",
    "config/reference-policy.yaml",
    "config/validation-gates.json",
    "config/extension-schema-registry.json",
    "taxonomies/source-kinds.yaml",
    "taxonomies/evidence-kinds.yaml",
    "taxonomies/semantic-roles.yaml",
    "prompts/semantic-asset.prompt.md",
    "prompts/business-model.prompt.md",
    "prompts/relationship-adjudication.prompt.md",
    "prompts/unstructured-content.prompt.md",
    "features/source-onboarding.feature",
    "features/structural-and-statistical-profiling.feature",
    "features/semantic-and-business-model.feature",
    "features/identity-and-relationships.feature",
    "features/agent-consumption.feature",
    "features/universal-source-types.feature",
    "features/operations-and-governance.feature",
    "examples/source-descriptor.json",
    "examples/source-registration-request.json",
    "examples/source-boundary-opening.json",
    "examples/source-boundary-verification.json",
    "examples/source-structure.json",
    "examples/source-value-fingerprint-set.json",
    "examples/projection-safety-receipt.json",
    "examples/stage-receipt-bundle.json",
    "examples/stage-output-details.json",
    "examples/evidence-record.json",
    "examples/evidence-bundle.json",
    "examples/cross-scope-relationship-validation.json",
    "examples/profiling-run.json",
    "examples/profiling-run-pending.json",
    "examples/profiling-run-running.json",
    "examples/profiling-run-resume.json",
    "examples/work-progress-page-0001.json",
    "examples/work-progress-manifest.json",
    "examples/evidence-response.json",
    "examples/execution-budget-bundle.json",
    "examples/deletion-inventory-page-0001.json",
    "examples/deletion-inventory-active.json",
    "examples/deletion-inventory-manifest.json",
    "examples/publication-receipt.json",
    "examples/cancellation-request.json",
    "examples/cancellation-receipt.json",
    "examples/feedback-request.json",
    "examples/feedback-receipt.json",
    "examples/read-plan-validation-context.json",
    "examples/read-execution-result.json",
    "examples/retrieval-bundle.json",
    "examples/profile-manifest.json",
    "examples/capability-manifest.json",
    "examples/read-plan.json",
    "examples/read-plan-validation-receipt.json",
    "examples/deletion-receipt.json",
    "examples/audit-event.json",
    "examples/cancellation-audit-event.json",
    "examples/feedback-audit-event.json",
    "examples/model-execution.json",
    "examples/model-parameters.json",
    "examples/model-redacted-input.json",
    "examples/parser-execution.json",
    "security/registration-negative-cases.json",
    "security/trusted-issuers.json",
    "benchmark/corpus.json",
    "benchmark/comparison.json",
    "scripts/validation_control.py",
    "scripts/validate_package.py",
    "scripts/run_tests.py",
    "scripts/evaluate_benchmark.py",
    "tests/test_validate_package.py",
    "requirements-validation.txt",
]

EXAMPLE_SCHEMA_PAIRS = [
    ("examples/source-registration-request.json", "contracts/source-registration-request.schema.json"),
    ("examples/source-boundary-opening.json", "contracts/source-boundary.schema.json"),
    ("examples/source-boundary-verification.json", "contracts/source-boundary.schema.json"),
    ("examples/source-structure.json", "contracts/source-structure.schema.json"),
    ("examples/source-value-fingerprint-set.json", "contracts/source-value-fingerprint-set.schema.json"),
    ("examples/projection-safety-receipt.json", "contracts/projection-safety-receipt.schema.json"),
    ("examples/stage-receipt-bundle.json", "contracts/stage-receipt-bundle.schema.json"),
    ("examples/stage-output-details.json", "contracts/stage-output-details.schema.json"),
    ("examples/source-descriptor.json", "contracts/source-descriptor.schema.json"),
    ("examples/evidence-record.json", "contracts/evidence-record.schema.json"),
    ("examples/evidence-bundle.json", "contracts/evidence-bundle.schema.json"),
    ("examples/cross-scope-relationship-validation.json", "contracts/relationship-validation.schema.json"),
    ("examples/profiling-run.json", "contracts/profiling-run.schema.json"),
    ("examples/profiling-run-pending.json", "contracts/profiling-run.schema.json"),
    ("examples/profiling-run-running.json", "contracts/profiling-run.schema.json"),
    ("examples/profiling-run-resume.json", "contracts/profiling-run.schema.json"),
    ("examples/work-progress-page-0001.json", "contracts/work-progress-page.schema.json"),
    ("examples/work-progress-manifest.json", "contracts/work-progress-manifest.schema.json"),
    ("examples/evidence-response.json", "contracts/evidence-response.schema.json"),
    ("examples/execution-budget-bundle.json", "contracts/execution-budget-bundle.schema.json"),
    ("examples/deletion-inventory-page-0001.json", "contracts/deletion-inventory-page.schema.json"),
    ("examples/deletion-inventory-active.json", "contracts/deletion-inventory-manifest.schema.json"),
    ("examples/deletion-inventory-manifest.json", "contracts/deletion-inventory-manifest.schema.json"),
    ("examples/publication-receipt.json", "contracts/publication-receipt.schema.json"),
    ("examples/cancellation-receipt.json", "contracts/cancellation-receipt.schema.json"),
    ("examples/feedback-receipt.json", "contracts/feedback-receipt.schema.json"),
    ("examples/read-execution-result.json", "contracts/read-execution-result.schema.json"),
    ("examples/retrieval-bundle.json", "contracts/retrieval-bundle.schema.json"),
    ("examples/profile-manifest.json", "contracts/profile-manifest.schema.json"),
    ("examples/capability-manifest.json", "contracts/capability-manifest.schema.json"),
    ("examples/read-plan.json", "contracts/read-plan.schema.json"),
    ("examples/read-plan-validation-receipt.json", "contracts/read-plan-validation-receipt.schema.json"),
    ("examples/deletion-receipt.json", "contracts/deletion-receipt.schema.json"),
    ("examples/audit-event.json", "contracts/audit-event.schema.json"),
    ("examples/cancellation-audit-event.json", "contracts/audit-event.schema.json"),
    ("examples/feedback-audit-event.json", "contracts/audit-event.schema.json"),
    ("examples/model-execution.json", "contracts/model-execution.schema.json"),
    ("examples/parser-execution.json", "contracts/parser-execution.schema.json"),
    ("benchmark/corpus.json", "contracts/benchmark-corpus.schema.json"),
    ("benchmark/comparison.json", "contracts/benchmark-comparison.schema.json"),
    ("requirements/catalog.json", "requirements/catalog.schema.json"),
]

# Neutral sentinels exercise the distributable privacy gate without embedding
# names or identifiers from any source organization, person, product, or service.
FORBIDDEN_PATTERNS = [
    r"private-source-marker",
    r"source-organization-marker",
    r"source-project-marker",
    r"source-product-marker",
    r"source-service-marker",
    r"source-team-marker",
    r"source-person-marker",
    r"source-email-marker",
    r"source-tenant-marker",
    r"source-account-marker",
    r"source-resource-marker",
    r"source-host-marker",
    r"source-path-marker",
]

PLACEHOLDER_PATTERNS = [
    r"\bTBD\b",
    r"\bTODO\b",
    r"\bFIXME\b",
    r"not yet implemented",
    r"placeholder implementation",
]

EMAIL_ADDRESS_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)
ABSOLUTE_DOMAIN_PATTERN = re.compile(
    r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?(?:[/?#]|$)",
    re.IGNORECASE,
)
USER_PROFILE_PATH_PATTERNS = [
    re.compile(r"\b[A-Za-z]:\\Users\\[^\\\s]+", re.IGNORECASE),
    re.compile(r"/(?:Users|home)/[^/\s]+", re.IGNORECASE),
]
DEPLOYED_RESOURCE_PATH_PATTERN = re.compile(
    r"/subscriptions/[0-9a-f]{8}-[0-9a-f-]{27}/resourcegroups/",
    re.IGNORECASE,
)


def is_approved_document_domain(domain: str) -> bool:
    normalized = domain.casefold().rstrip(".")
    return normalized == "json-schema.org" or normalized.endswith(".invalid")


class Validation:
    def __init__(self) -> None:
        self.checks = 0
        self.errors: list[str] = []
        self.gate_executions: list[dict[str, Any]] = []

    def check(self, condition: bool, message: str) -> None:
        self.checks += 1
        if not condition:
            self.errors.append(message)


def load_json(relative_path: str, validation: Validation) -> Any:
    path = ROOT / relative_path
    try:
        maximum_bytes = 16_777_216
        policy_path = ROOT / "config" / "reference-policy.yaml"
        if policy_path.is_file() and policy_path.stat().st_size <= maximum_bytes:
            import yaml  # type: ignore[import-not-found]
            configured = yaml.safe_load(policy_path.read_text(encoding="utf-8")).get("validation", {}).get("maximumArtifactBytes")
            if type(configured) is int and configured > 0:
                maximum_bytes = configured
        size = path.stat().st_size
        if size > maximum_bytes:
            validation.check(False, f"JSON artifact {relative_path} exceeds maximum validation artifact bytes ({size} > {maximum_bytes})")
            return None

        def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate object key {key!r}")
                result[key] = value
            return result

        def reject_constant(value: str) -> None:
            raise ValueError(f"non-standard JSON constant {value!r}")

        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except Exception as exc:  # noqa: BLE001 - validator must aggregate failures
        validation.check(False, f"JSON parse failed for {relative_path}: {exc}")
        return None


def resolve_pointer(root_schema: dict[str, Any], reference: str) -> dict[str, Any] | None:
    if not reference.startswith("#/"):
        return None
    current: Any = root_schema
    for segment in reference[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current if isinstance(current, dict) else None


def is_type(instance: Any, expected: str) -> bool:
    if expected == "null":
        return instance is None
    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    return True


def validate_format(value: str, format_name: str) -> bool:
    if format_name == "uuid":
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False
    if format_name == "date-time":
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False
    if format_name == "uri-reference":
        return bool(value) and " " not in value
    return True


def validate_schema(
    instance: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    path: str,
    errors: list[str],
    schema_path: Path | None = None,
) -> None:
    if "$ref" in schema:
        reference = schema["$ref"]
        if reference.startswith("#/"):
            resolved = resolve_pointer(root_schema, reference)
            if resolved is None:
                errors.append(f"{path}: unresolved schema reference {reference}")
                return
            validate_schema(instance, resolved, root_schema, path, errors, schema_path)
            return

        file_reference, _, fragment = reference.partition("#")
        base_directory = schema_path.parent if schema_path is not None else ROOT / "contracts"
        target_path = (base_directory / file_reference).resolve()
        try:
            target_schema = json.loads(target_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - validator aggregates failures
            errors.append(f"{path}: unable to load schema reference {reference}: {exc}")
            return
        resolved = target_schema
        if fragment:
            resolved = resolve_pointer(target_schema, f"#/{fragment.lstrip('/')}")
        if not isinstance(resolved, dict):
            errors.append(f"{path}: unresolved schema fragment {reference}")
            return
        validate_schema(instance, resolved, target_schema, path, errors, target_path)
        return

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} is not in enum {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(is_type(instance, item) for item in allowed_types):
            errors.append(f"{path}: expected type {allowed_types!r}, got {type(instance).__name__}")
            return

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: string shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: string longer than maxLength {schema['maxLength']}")
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            errors.append(f"{path}: string does not match pattern {schema['pattern']}")
        if "format" in schema and not validate_format(instance, schema["format"]):
            errors.append(f"{path}: invalid {schema['format']} value")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: value below minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: value above maximum {schema['maximum']}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: array shorter than minItems {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: array longer than maxItems {schema['maxItems']}")
        if schema.get("uniqueItems"):
            canonical = [json.dumps(item, sort_keys=True) for item in instance]
            if len(canonical) != len(set(canonical)):
                errors.append(f"{path}: array items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                validate_schema(item, item_schema, root_schema, f"{path}[{index}]", errors, schema_path)
        contains_schema = schema.get("contains")
        if isinstance(contains_schema, dict):
            matches = 0
            for index, item in enumerate(instance):
                contains_errors: list[str] = []
                validate_schema(item, contains_schema, root_schema, f"{path}[{index}]", contains_errors, schema_path)
                if not contains_errors:
                    matches += 1
            minimum_contains = schema.get("minContains", 1)
            maximum_contains = schema.get("maxContains")
            if matches < minimum_contains:
                errors.append(f"{path}: contains matched {matches} items; expected at least {minimum_contains}")
            if maximum_contains is not None and matches > maximum_contains:
                errors.append(f"{path}: contains matched {matches} items; expected at most {maximum_contains}")

    if isinstance(instance, dict):
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            errors.append(f"{path}: object has fewer than minProperties {schema['minProperties']}")
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            errors.append(f"{path}: object has more than maxProperties {schema['maxProperties']}")
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append(f"{path}: missing required property {key}")

        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected property {key}")
        elif isinstance(additional, dict):
            for key, value in instance.items():
                if key not in properties:
                    validate_schema(value, additional, root_schema, f"{path}.{key}", errors, schema_path)

        for key, property_schema in properties.items():
            if key in instance and isinstance(property_schema, dict):
                validate_schema(instance[key], property_schema, root_schema, f"{path}.{key}", errors, schema_path)

    # Evaluate general allOf members and the conditional members used by the contracts.
    for rule in schema.get("allOf", []):
        if "if" not in rule:
            validate_schema(instance, rule, root_schema, path, errors, schema_path)
            continue
        condition = rule.get("if", {}).get("properties", {})
        matches = True
        for key, key_schema in condition.items():
            if not isinstance(instance, dict) or key not in instance:
                matches = False
                break
            condition_errors: list[str] = []
            validate_schema(instance[key], key_schema, root_schema, f"{path}.{key}", condition_errors, schema_path)
            if condition_errors:
                matches = False
                break
        if matches and "then" in rule:
            validate_schema(instance, rule["then"], root_schema, path, errors, schema_path)


def validate_artifacts(validation: Validation) -> None:
    try:
        import yaml  # type: ignore[import-not-found]
        package_manifest = yaml.safe_load((ROOT / "package.yaml").read_text(encoding="utf-8"))
        manifest_artifacts = package_manifest.get("artifacts", []) if isinstance(package_manifest, dict) else []
        validation.check(manifest_artifacts == EXPECTED_ARTIFACTS, "package.yaml artifact inventory differs from the validator inventory")
        validation.check(len(manifest_artifacts) == len(set(manifest_artifacts)), "package.yaml artifact inventory contains duplicates")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read package.yaml artifact inventory: {exc}")
    for relative_path in EXPECTED_ARTIFACTS:
        path = ROOT / relative_path
        validation.check(path.is_file(), f"Missing package artifact: {relative_path}")
        if path.is_file():
            validation.check(path.stat().st_size > 0, f"Empty package artifact: {relative_path}")
    declared = set(EXPECTED_ARTIFACTS)
    governed_roots = {
        "benchmark", "config", "contracts", "docs", "examples", "features", "pipeline",
        "prompts", "requirements", "scripts", "security", "taxonomies", "tests",
    }
    actual = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.relative_to(ROOT).parts[0] in governed_roots
        and "CodeReview" not in path.relative_to(ROOT).parts
        and path.suffix != ".tmp"
    }
    for relative_path in sorted(
        relative_path
        for relative_path in actual
        if "__pycache__" in Path(relative_path).parts or Path(relative_path).suffix in {".pyc", ".pyo"}
    ):
        validation.check(False, f"Forbidden compiled/cache artifact: {relative_path}")
    actual = {
        relative_path
        for relative_path in actual
        if "__pycache__" not in Path(relative_path).parts and Path(relative_path).suffix not in {".pyc", ".pyo"}
    }
    for relative_path in sorted(actual - declared):
        validation.check(False, f"Undeclared package artifact: {relative_path}")


def validate_json_and_examples(validation: Validation) -> None:
    json_files = sorted(ROOT.rglob("*.json"))
    validation.check(len(json_files) > 0, "No JSON files found")
    for path in json_files:
        relative = path.relative_to(ROOT).as_posix()
        load_json(relative, validation)

    for example_path, schema_path in EXAMPLE_SCHEMA_PAIRS:
        instance = load_json(example_path, validation)
        schema = load_json(schema_path, validation)
        if instance is None or schema is None:
            continue
        schema_errors: list[str] = []
        validate_schema(instance, schema, schema, "$", schema_errors, ROOT / schema_path)
        validation.check(
            not schema_errors,
            f"{example_path} failed {schema_path}: " + "; ".join(schema_errors),
        )


def parse_features(validation: Validation) -> dict[str, set[str]]:
    """Parse features with the standards Gherkin parser and return scenario names per feature."""
    try:
        from gherkin.parser import Parser  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Gherkin parser missing ({exc}); run: python -m pip install -r requirements-validation.txt")
        return {}

    parser = Parser()
    scenarios_by_feature: dict[str, set[str]] = {}
    for path in sorted((ROOT / "features").glob("*.feature")):
        try:
            document = parser.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Gherkin parse failed for {path.name}: {exc}")
            continue
        feature = document.get("feature")
        validation.check(feature is not None, f"Missing Feature declaration: {path.name}")
        if feature is None:
            continue
        names: set[str] = set()
        for child in feature.get("children", []):
            scenario = child.get("scenario")
            if scenario is None:
                continue
            name = scenario.get("name", "").strip()
            keywords = {step.get("keyword", "").strip() for step in scenario.get("steps", [])}
            validation.check(name not in names, f"Duplicate scenario name in {path.name}: {name}")
            names.add(name)
            validation.check("Given" in keywords, f"Scenario lacks Given: {path.name}:{name}")
            validation.check("When" in keywords, f"Scenario lacks When: {path.name}:{name}")
            validation.check("Then" in keywords, f"Scenario lacks Then: {path.name}:{name}")
        validation.check(len(names) > 0, f"No scenarios found: {path.name}")
        scenarios_by_feature[path.stem] = names
    return scenarios_by_feature


def parse_feature_tags(validation: Validation) -> dict[str, dict[str, set[str]]]:
    """Return normalized Gherkin tags per feature/scenario for semantic traceability."""
    try:
        from gherkin.parser import Parser  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Gherkin parser missing ({exc})")
        return {}
    parser = Parser()
    result: dict[str, dict[str, set[str]]] = {}
    for path in sorted((ROOT / "features").glob("*.feature")):
        try:
            document = parser.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Gherkin tag parse failed for {path.name}: {exc}")
            continue
        scenarios: dict[str, set[str]] = {}
        for child in document.get("feature", {}).get("children", []):
            scenario = child.get("scenario")
            if scenario is not None:
                scenarios[scenario.get("name", "").strip()] = {tag.get("name", "") for tag in scenario.get("tags", [])}
        result[path.stem] = scenarios
    return result


def parse_feature_outcomes(validation: Validation) -> dict[str, dict[str, list[str]]]:
    """Return exact outcome-phase steps for every parsed Gherkin scenario."""
    try:
        from gherkin.parser import Parser  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Gherkin parser missing ({exc})")
        return {}
    parser = Parser()
    result: dict[str, dict[str, list[str]]] = {}
    for path in sorted((ROOT / "features").glob("*.feature")):
        try:
            document = parser.parse(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Gherkin outcome parse failed for {path.name}: {exc}")
            continue
        scenarios: dict[str, list[str]] = {}
        for child in document.get("feature", {}).get("children", []):
            scenario = child.get("scenario")
            if scenario is None:
                continue
            outcomes: list[str] = []
            in_outcome = False
            for step in scenario.get("steps", []):
                keyword_type = step.get("keywordType")
                if keyword_type == "Outcome":
                    in_outcome = True
                    outcomes.append(step.get("text", "").strip())
                elif keyword_type == "Conjunction" and in_outcome:
                    outcomes.append(step.get("text", "").strip())
                else:
                    in_outcome = False
            scenarios[scenario.get("name", "").strip()] = outcomes
        result[path.stem] = scenarios
    return result


def validate_agent_response_bounds(validation: Validation) -> None:
    """Free text returned to an agent must be bounded and provenance-marked."""
    try:
        import yaml  # type: ignore[import-not-found]
        specification = yaml.safe_load((ROOT / "contracts" / "api.openapi.yaml").read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read the API surface: {exc}")
        return

    def walk(node: Any, path: str, schema_name: str, visited_refs: set[str], global_text_bound: bool) -> None:
        if isinstance(node, dict):
            reference = node.get("$ref")
            if isinstance(reference, str) and reference.startswith("./") and reference not in visited_refs:
                visited_refs.add(reference)
                target = ROOT / "contracts" / reference[2:].split("#", 1)[0]
                validation.check(target.is_file(), f"Agent-facing schema {schema_name} references missing contract {reference}")
                if target.is_file():
                    external = json.loads(target.read_text(encoding="utf-8"))
                    _, _, fragment = reference.partition("#")
                    resolved = external if not fragment else resolve_pointer(external, f"#/{fragment.lstrip('/')}")
                    if isinstance(resolved, dict):
                        walk(resolved, path, schema_name, visited_refs, global_text_bound)
                return
            declared = node.get("type")
            types = declared if isinstance(declared, list) else [declared]
            if "string" in types and not {"enum", "format", "pattern"} & set(node):
                validation.check("maxLength" in node or global_text_bound, f"Unbounded agent-facing string at {schema_name}{path}")
            if "object" in types and "additionalProperties" not in node and "properties" not in node and not global_text_bound:
                validation.check(False, f"Unconstrained agent-facing object at {schema_name}{path}")
            if "array" in types:
                validation.check("maxItems" in node or path.endswith("Refs") or global_text_bound, f"Unbounded agent-facing array at {schema_name}{path}")
            for key, child in node.items():
                if isinstance(child, (dict, list)):
                    walk(child, f"{path}.{key}", schema_name, visited_refs, global_text_bound)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{path}[{index}]", schema_name, visited_refs, global_text_bound)

    schemas = specification.get("components", {}).get("schemas", {})
    for name in ("ProfileManifest", "CapabilityManifest", "EvidenceResponse", "RetrievalBundle", "ReadExecutionResult", "SafeProblem"):
        schema = schemas.get(name)
        validation.check(isinstance(schema, dict), f"The API surface declares no {name}")
        if isinstance(schema, dict):
            has_response_policy = name in {"ProfileManifest", "CapabilityManifest", "EvidenceResponse", "RetrievalBundle", "ReadExecutionResult"}
            if has_response_policy:
                reference = schema.get("$ref")
                target = ROOT / "contracts" / reference.removeprefix("./") if isinstance(reference, str) and reference.startswith("./") else None
                document = json.loads(target.read_text(encoding="utf-8")) if target is not None and target.is_file() else schema
                validation.check("responsePolicy" in document.get("required", []), f"{name} does not require a response safety policy")
                validation.check(document.get("properties", {}).get("responsePolicy", {}).get("$ref") == "agent-response-policy.schema.json", f"{name} response safety policy is not contract-bound")
            walk(schema, "", name, set(), has_response_policy)

    bundle = load_json("contracts/retrieval-bundle.schema.json", validation)
    if not isinstance(bundle, dict):
        return
    item = bundle.get("properties", {}).get("items", {}).get("items", {})
    validation.check("contentProvenance" in item.get("required", []), "Retrieval items do not declare content provenance")
    coordinate_ref = bundle.get("properties", {}).get("coordinate", {}).get("$ref")
    validation.check(coordinate_ref == "projection-coordinate.schema.json", "The retrieval bundle does not carry the complete projection coordinate")


def validate_openapi_references(validation: Validation) -> None:
    """External $refs in the API surface must resolve to a real contract file and fragment."""
    path = ROOT / "contracts" / "api.openapi.yaml"
    text = path.read_text(encoding="utf-8")
    references = set(re.findall(r"\$ref:\s*'?(\./[\w.-]+\.schema\.json(?:#[^\s'\"]*)?)'?", text))
    validation.check(len(references) > 0, "The API surface declares no external contract references")
    for reference in sorted(references):
        file_part, _, fragment = reference.partition("#")
        target = (path.parent / file_part).resolve()
        validation.check(target.is_file(), f"API surface references a missing contract file: {reference}")
        if not target.is_file() or not fragment:
            continue
        try:
            schema = json.loads(target.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"API surface reference could not be parsed: {reference}: {exc}")
            continue
        validation.check(
            isinstance(resolve_pointer(schema, f"#/{fragment.lstrip('/')}"), dict),
            f"API surface references a missing contract fragment: {reference}",
        )


def validate_protected_resource_errors(validation: Validation) -> None:
    """Absent and inaccessible protected identifiers must be observationally identical."""
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"YAML library missing ({exc})")
        return

    specification = yaml.safe_load((ROOT / "contracts" / "api.openapi.yaml").read_text(encoding="utf-8"))
    control = load_json("config/validation-gates.json", validation)
    expected_operations = set(control.get("protectedOperationIds", [])) if isinstance(control, dict) else set()
    protected_response = "#/components/responses/ProtectedResourceUnavailable"
    observed_operations: set[str] = set()
    for path, path_item in specification.get("paths", {}).items():
        for method, operation in path_item.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation_id = operation.get("operationId")
            if operation_id not in expected_operations:
                continue
            observed_operations.add(operation_id)
            responses = operation.get("responses", {})
            validation.check("403" not in responses, f"Protected operation {method.upper()} {path} exposes a distinguishable 403")
            validation.check(
                responses.get("404", {}).get("$ref") == protected_response,
                f"Protected operation {method.upper()} {path} does not use the indistinguishable resource response",
            )
    validation.check(observed_operations == expected_operations, "Protected operation inventory differs from the API contract")

    schemas = specification.get("components", {}).get("schemas", {})
    protected = schemas.get("ProtectedResourceProblem", {}).get("properties", {})
    expected_constants = {
        "type": "urn:agent-data-profiler:resource-unavailable",
        "title": "Resource unavailable",
        "status": 404,
        "reasonCode": "RESOURCE_UNAVAILABLE",
    }
    for field, value in expected_constants.items():
        validation.check(protected.get(field, {}).get("const") == value, f"Protected resource problem has no fixed {field}")
    validation.check(protected.get("detail", {}).get("type") == "null", "Protected resource detail can disclose request-specific information")

    safe_values = schemas.get("SafeProblem", {}).get("properties", {}).get("detail", {}).get("enum", [])
    allowed_details = {None, "Request rejected.", "Request conflicts with current state.", "Request limit exceeded."}
    validation.check(None in safe_values, "Generic problem detail cannot be null")
    validation.check(bool(safe_values) and set(safe_values) <= allowed_details, "Generic problem detail permits runtime-composed text")


def validate_audit_chain(validation: Validation) -> None:
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
        return

    events = [
        load_json("examples/audit-event.json", validation),
        load_json("examples/cancellation-audit-event.json", validation),
        load_json("examples/feedback-audit-event.json", validation),
    ]
    if not all(isinstance(event, dict) for event in events):
        return
    context = load_json("examples/read-plan-validation-context.json", validation)
    if not isinstance(context, dict):
        return
    caller = context.get("validatedCaller", {})
    subject_hashing = context.get("subjectHashing", {})
    caller_hash = hashlib.sha256(
        rfc8785.dumps(["caller-subject-v1", subject_hashing.get("deploymentSalt"), caller.get("tenantId"), caller.get("subjectId")])
    ).hexdigest()
    previous_hash = None
    previous_time = None
    events_by_id = {}
    for sequence, event in enumerate(events):
        events_by_id[event.get("eventId")] = event
        integrity = event.get("integrity", {})
        validation.check(event.get("sequenceNumber") == sequence, f"Audit event {event.get('eventId')} has a non-contiguous sequence number")
        validation.check(integrity.get("hashAlgorithm") == "sha256-jcs", f"Audit event {event.get('eventId')} declares no canonical hash algorithm")
        validation.check(integrity.get("previousEventSha256") == previous_hash, f"Audit event {event.get('eventId')} predecessor link is incorrect")
        body = {key: value for key, value in event.items() if key != "integrity"}
        body["integrity"] = {"previousEventSha256": previous_hash}
        expected = hashlib.sha256(rfc8785.dumps(body)).hexdigest()
        validation.check(integrity.get("payloadSha256") == expected, f"Audit event {event.get('eventId')} payloadSha256 mismatch: expected {expected}")
        occurred = datetime.fromisoformat(event["occurredAt"].replace("Z", "+00:00"))
        if previous_time is not None:
            validation.check(previous_time <= occurred, f"Audit event {event.get('eventId')} occurs before its predecessor")
        previous_time = occurred
        previous_hash = expected

        authorization = event.get("authorization", {})
        actor = event.get("actor", {})
        validation.check(actor.get("subjectId") == caller_hash, f"Audit event {event.get('eventId')} actor differs from the validated caller")
        validation.check(actor.get("subjectHashSaltId") == subject_hashing.get("saltId"), f"Audit event {event.get('eventId')} actor hash salt differs from verifier context")
        required = set(authorization.get("requiredPermissions", []))
        granted = set(authorization.get("grantedPermissions", []))
        if authorization.get("decision") == "allowed":
            validation.check(required <= granted, f"Audit event {event.get('eventId')} was allowed without all required permissions")
            validation.check(event.get("outcome") != "denied", f"Allowed audit event {event.get('eventId')} reports a denied outcome")
        else:
            validation.check(event.get("outcome") == "denied", f"Denied audit event {event.get('eventId')} reports a non-denied outcome")
            validation.check(bool(authorization.get("reasonCode")), f"Denied audit event {event.get('eventId')} has no reason code")

    cancellation = load_json("examples/cancellation-receipt.json", validation)
    feedback = load_json("examples/feedback-receipt.json", validation)
    if isinstance(cancellation, dict):
        event = events_by_id.get(cancellation.get("auditEventId"))
        validation.check(event is not None and event.get("action") == "run.cancel", "Cancellation receipt is not bound to a run.cancel audit event")
        if event is not None:
            validation.check(event.get("requestSummary", {}).get("cancellationId") == cancellation.get("cancellationId"), "Cancellation audit event names a different request")
    if isinstance(feedback, dict):
        event = events_by_id.get(feedback.get("auditEventId"))
        validation.check(event is not None and event.get("action") == "feedback.submit", "Feedback receipt is not bound to a feedback.submit audit event")
        if event is not None:
            validation.check(event.get("resultSummary", {}).get("feedbackEvidenceId") == feedback.get("feedbackEvidenceId"), "Feedback audit event names different created evidence")


def validate_trusted_receipts(validation: Validation) -> None:
    """Verify signatures and policy bindings for trusted authorization and redaction decisions."""
    try:
        import rfc8785  # type: ignore[import-not-found]
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        validation.check(False, f"Signature validation dependency missing ({exc}); run: python -m pip install -r requirements-validation.txt")
        return

    try:
        registry = load_trusted_issuers(
            ROOT,
            issuer_registry_path=TRUST_REGISTRY_PATH,
            expected_registry_sha256=TRUST_REGISTRY_SHA256,
            require_external=REQUIRE_EXTERNAL_TRUST,
        )
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Trusted issuer registry verification failed: {exc}")
        return
    bundle = load_json("examples/evidence-bundle.json", validation)
    publication = load_json("examples/publication-receipt.json", validation)
    cross_scope = load_json("examples/cross-scope-relationship-validation.json", validation)
    profile = load_json("examples/profile-manifest.json", validation)
    context = load_json("examples/read-plan-validation-context.json", validation)
    read_receipt = load_json("examples/read-plan-validation-receipt.json", validation)
    stage_bundle = load_json("examples/stage-receipt-bundle.json", validation)
    if not all(isinstance(value, dict) for value in (registry, bundle, publication, cross_scope, profile, context, read_receipt, stage_bundle)):
        return

    issuer_rows = [row for row in registry.get("issuers", []) if isinstance(row, dict)]
    issuers = {row.get("issuerKeyId"): row for row in issuer_rows}
    validation.check(len(issuers) == len(issuer_rows), "Trusted issuer registry contains duplicate key IDs")

    def verify(receipt: dict[str, Any], purpose: str, message: bytes, event_time_field: str) -> None:
        key_id = receipt.get("issuerKeyId")
        issuer = issuers.get(key_id)
        validation.check(issuer is not None, f"{purpose} receipt names untrusted issuer {key_id}")
        if issuer is None:
            return
        validation.check(purpose in issuer.get("purposes", []), f"Issuer {key_id} is not authorized for {purpose}")
        validation.check(receipt.get("signatureAlgorithm") == issuer.get("algorithm") == "ed25519", f"{purpose} receipt uses an untrusted signature algorithm")
        try:
            event_time = datetime.fromisoformat(receipt[event_time_field].replace("Z", "+00:00"))
            valid_from = datetime.fromisoformat(issuer["validFrom"].replace("Z", "+00:00"))
            valid_until = datetime.fromisoformat(issuer["validUntil"].replace("Z", "+00:00"))
            validation.check(valid_from <= event_time < valid_until, f"{purpose} receipt was signed outside the issuer validity window")
        except (KeyError, TypeError, ValueError) as exc:
            validation.check(False, f"{purpose} receipt or issuer has an invalid trust timestamp: {exc}")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(issuer.get("publicKeyBase64", ""), validate=True))
            public_key.verify(base64.b64decode(receipt.get("signature", ""), validate=True), message)
            validation.check(True, f"{purpose} receipt signature verified")
        except (ValueError, InvalidSignature) as exc:
            validation.check(False, f"{purpose} receipt signature verification failed: {exc}")

    for record in bundle.get("records", []):
        receipt = record.get("redactionReceipt")
        validation.check(isinstance(receipt, dict), f"Evidence {record.get('evidenceId')} has no signed redaction receipt")
        if not isinstance(receipt, dict):
            continue
        verify(receipt, "redaction", rfc8785.dumps({key: value for key, value in receipt.items() if key != "signature"}), "scannedAt")
        for key in ("payloadHash", "sourceId", "sourceVersion", "authorizationScopeId", "policyHash"):
            validation.check(receipt.get(key) == record.get(key), f"Evidence {record.get('evidenceId')} redaction receipt {key} differs from the record")
        evidence_envelope = {
            key: record.get(key)
            for key in ("evidenceId", "logicalKey", "revocationEpoch", "fencingToken", "claim", "payload", "dataHandling")
        }
        expected_content_hash = hashlib.sha256(rfc8785.dumps(evidence_envelope)).hexdigest()
        validation.check(receipt.get("contentHash") == expected_content_hash, f"Evidence {record.get('evidenceId')} redaction receipt does not cover its complete evidence envelope")
        handling = record.get("dataHandling", {})
        validation.check(receipt.get("classification") == handling.get("classification"), f"Evidence {record.get('evidenceId')} redaction classification differs from data handling")
        validation.check(receipt.get("containsRawSourceValues") == handling.get("containsRawSourceValues") is False, f"Evidence {record.get('evidenceId')} is not attested raw-value-free")
        validation.check(receipt.get("minimumGroupSizeApplied") == handling.get("minimumGroupSizeApplied"), f"Evidence {record.get('evidenceId')} redaction group size differs from data handling")

    extensions = [row for row in profile.get("sourceExtensions", []) if isinstance(row, dict)]
    validation.check(bool(extensions), "Profile manifest exercises no source-extension conformance vector")
    asset_ids = {row.get("assetId") for row in profile.get("assets", []) if isinstance(row, dict)}
    evidence_ids = {row.get("evidenceId") for row in bundle.get("records", []) if isinstance(row, dict)}
    for extension in extensions:
        receipt = extension.get("redactionReceipt")
        validation.check(isinstance(receipt, dict), f"Extension {extension.get('extensionId')} has no signed redaction receipt")
        if not isinstance(receipt, dict):
            continue
        verify(receipt, "redaction", rfc8785.dumps({key: value for key, value in receipt.items() if key != "signature"}), "scannedAt")
        expected_payload_hash = hashlib.sha256(rfc8785.dumps(extension.get("payload"))).hexdigest()
        extension_envelope = {
            key: extension.get(key)
            for key in ("extensionId", "extensionVersion", "assetId", "sourceKind", "connectorId", "connectorVersion", "connectorCapabilityHash", "revocationEpoch", "payloadKind", "payloadSchemaId", "payloadSchemaVersion", "payloadSchemaHash", "payloadHash", "dataHandling", "evidenceRefs")
        }
        expected_content_hash = hashlib.sha256(rfc8785.dumps(extension_envelope)).hexdigest()
        validation.check(extension.get("payloadHash") == expected_payload_hash, f"Extension {extension.get('extensionId')} payloadHash mismatch")
        validation.check(receipt.get("payloadHash") == expected_payload_hash, f"Extension {extension.get('extensionId')} receipt names a different payload")
        validation.check(receipt.get("contentHash") == expected_content_hash, f"Extension {extension.get('extensionId')} receipt does not cover its complete extension envelope")
        for key in ("sourceId", "sourceVersion", "authorizationScopeId", "policyHash"):
            validation.check(receipt.get(key) == extension.get(key), f"Extension {extension.get('extensionId')} redaction receipt {key} differs from the extension")
        handling = extension.get("dataHandling", {})
        validation.check(receipt.get("classification") == handling.get("classification"), f"Extension {extension.get('extensionId')} redaction classification differs from data handling")
        validation.check(receipt.get("containsRawSourceValues") == handling.get("containsRawSourceValues") is False, f"Extension {extension.get('extensionId')} is not attested raw-value-free")
        validation.check(receipt.get("minimumGroupSizeApplied") == handling.get("minimumGroupSizeApplied"), f"Extension {extension.get('extensionId')} redaction group size differs from data handling")
        validation.check(extension.get("assetId") in asset_ids, f"Extension {extension.get('extensionId')} names a missing asset")
        for evidence_id in extension.get("evidenceRefs", []):
            validation.check(evidence_id in evidence_ids, f"Extension {extension.get('extensionId')} cites missing evidence {evidence_id}")

    publication_message = bytes.fromhex(publication.get("receiptHash", "")) if re.fullmatch(r"[a-fA-F0-9]{64}", publication.get("receiptHash", "")) else b""
    verify(publication, "publication", publication_message, "publishedAt")
    stage_message = bytes.fromhex(stage_bundle.get("bundleHash", "")) if re.fullmatch(r"[a-fA-F0-9]{64}", stage_bundle.get("bundleHash", "")) else b""
    verify(stage_bundle, "stage-receipt", stage_message, "sealedAt")
    read_message = bytes.fromhex(read_receipt.get("receiptIntegrityHash", "")) if re.fullmatch(r"[a-fA-F0-9]{64}", read_receipt.get("receiptIntegrityHash", "")) else b""
    verify(read_receipt, "read-plan-validation", read_message, "issuedAt")

    grant = cross_scope.get("crossScopeAuthorizationReceipt")
    validation.check(isinstance(grant, dict), "Cross-scope conformance relationship has no signed grant")
    if isinstance(grant, dict):
        verify(grant, "cross-scope-authorization", rfc8785.dumps({key: value for key, value in grant.items() if key != "signature"}), "issuedAt")
        validation.check(grant.get("relationshipValidationId") == cross_scope.get("relationshipValidationId"), "Cross-scope grant names a different relationship")
        validation.check(grant.get("left") == {key: cross_scope.get("left", {}).get(key) for key in ("sourceId", "sourceVersion", "authorizationScopeId", "revocationEpoch")}, "Cross-scope grant left binding differs from its relationship")
        validation.check(grant.get("right") == {key: cross_scope.get("right", {}).get(key) for key in ("sourceId", "sourceVersion", "authorizationScopeId", "revocationEpoch")}, "Cross-scope grant right binding differs from its relationship")
        caller = context.get("validatedCaller", {})
        subject_hashing = context.get("subjectHashing", {})
        caller_hash = hashlib.sha256(
            rfc8785.dumps(["caller-subject-v1", subject_hashing.get("deploymentSalt"), caller.get("tenantId"), caller.get("subjectId")])
        ).hexdigest()
        validation.check(grant.get("actorSubjectHash") == caller_hash, "Cross-scope grant belongs to another caller")
        validation.check(grant.get("delegationChainHash") == caller.get("delegationChainHash"), "Cross-scope grant delegation chain differs from the caller")
        issued = datetime.fromisoformat(grant["issuedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(grant["expiresAt"].replace("Z", "+00:00"))
        used = datetime.fromisoformat(cross_scope["createdAt"].replace("Z", "+00:00"))
        validation.check(issued <= used < expires, "Cross-scope authorization was not valid when relationship validation completed")


def validate_projection_seal(validation: Validation) -> None:
    """Recompute immutable hashes and reconcile the full publication coordinate."""
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
        return

    run = load_json("examples/profiling-run.json", validation)
    profile = load_json("examples/profile-manifest.json", validation)
    capability = load_json("examples/capability-manifest.json", validation)
    publication = load_json("examples/publication-receipt.json", validation)
    read_receipt = load_json("examples/read-plan-validation-receipt.json", validation)
    parser = load_json("examples/parser-execution.json", validation)
    model = load_json("examples/model-execution.json", validation)
    bundle = load_json("examples/evidence-bundle.json", validation)
    source = load_json("examples/source-descriptor.json", validation)
    index_registry = load_json("pipeline/index-registry.json", validation)
    documents = (run, profile, capability, publication, read_receipt, parser, model, bundle, source, index_registry)
    if not all(isinstance(document, dict) for document in documents):
        return

    def digest(document: dict[str, Any], omitted: str) -> str:
        return hashlib.sha256(rfc8785.dumps({key: value for key, value in document.items() if key != omitted})).hexdigest()

    coordinate_keys = (
        "sourceId",
        "sourceVersion",
        "projectionId",
        "manifestVersion",
        "connectorId",
        "connectorVersion",
        "connectorCapabilityHash",
        "authorizationScopeId",
        "policyHash",
        "taxonomyVersion",
        "pipelineVersion",
        "methodSetHash",
        "evidenceCutoff",
        "revocationEpoch",
    )
    coordinate = {key: profile.get(key) for key in coordinate_keys}
    validation.check(source.get("sourceId") == coordinate["sourceId"], "Registered source ID differs from the sealed projection")
    for key in ("connectorId", "connectorVersion", "connectorCapabilityHash"):
        validation.check(source.get(key) == coordinate[key], f"Registered source {key} differs from the sealed projection")
    for name, document in (("run", run), ("capability manifest", capability), ("read-plan receipt", read_receipt)):
        for key in coordinate_keys:
            validation.check(document.get(key) == coordinate[key], f"{name} {key} differs from the sealed projection")
    validation.check(publication.get("coordinate") == coordinate, "Publication receipt coordinate differs from the sealed projection")
    validation.check(run.get("publicationReceiptId") == publication.get("receiptId"), "Run references a different publication receipt")
    validation.check(publication.get("runId") == run.get("runId"), "Publication receipt references a different run")
    validation.check(publication.get("fencingToken") == run.get("fencingToken"), "Publication receipt fencing token differs from the run")
    transition = publication.get("pointerTransition", {})
    expected_pointer_id = f"current:{coordinate.get('sourceId')}:{coordinate.get('authorizationScopeId')}"
    validation.check(transition.get("pointerId") == expected_pointer_id, "Publication pointer transition pointer ID is not derived from source and authorization scope")
    validation.check(transition.get("observedPreviousProjectionId") == publication.get("previousProjectionId"), "Publication pointer transition previous projection differs")
    validation.check(transition.get("newProjectionId") == coordinate.get("projectionId"), "Publication pointer transition new projection differs")
    validation.check(transition.get("newFencingToken") == publication.get("fencingToken"), "Publication pointer transition new fencing token differs")
    validation.check(transition.get("newFencingToken", 0) > transition.get("observedPreviousFencingToken", -1), "Publication pointer transition fencing token is not monotonic")
    transition_preimage = [
        transition.get("pointerId"),
        transition.get("observedPreviousProjectionId"),
        transition.get("observedPreviousFencingToken"),
        transition.get("newProjectionId"),
        transition.get("newFencingToken"),
        publication.get("coordinate", {}).get("policyHash"),
        publication.get("coordinate", {}).get("revocationEpoch"),
    ]
    validation.check(transition.get("compareAndSwapHash") == hashlib.sha256(rfc8785.dumps(transition_preimage)).hexdigest(), "Publication pointer transition compare-and-swap hash mismatch")
    validation.check(transition.get("assertedAt") == publication.get("publishedAt"), "Publication pointer transition assertion time differs from publication")
    validation.check(transition.get("outcome") == "signer-attested", "Publication pointer transition is not explicitly signer-attested")
    validation.check(transition.get("storageTransitionReceiptRef") is None, "Conformance publication unexpectedly claims a storage transition receipt")
    validation.check(transition.get("committed") is not True, "Publication cannot claim committed without a separate purpose-signed storage transition receipt")

    for name, document in (("profile manifest", profile), ("capability manifest", capability)):
        validation.check(document.get("hashAlgorithm") == "sha256-jcs", f"{name} declares no canonical hash algorithm")
        validation.check(document.get("contentHash") == digest(document, "contentHash"), f"{name} contentHash mismatch")

    stages = {row.get("stageId"): row for row in run.get("stages", []) if isinstance(row, dict)}
    parse_time = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    index_stage = stages.get("build-indexes", {})
    manifest_stage = stages.get("build-manifests", {})
    publish_stage = stages.get("publish", {})
    index_start, index_end = parse_time(index_stage.get("startedAt")), parse_time(index_stage.get("completedAt"))
    manifest_start, manifest_end = parse_time(manifest_stage.get("startedAt")), parse_time(manifest_stage.get("completedAt"))
    publish_start, publish_end = parse_time(publish_stage.get("startedAt")), parse_time(publish_stage.get("completedAt"))

    index_summaries = []
    required_index_kinds = {
        row.get("id")
        for row in index_registry.get("indexKinds", [])
        if isinstance(row, dict)
    }
    profile_index_kinds = [row.get("kind") for row in profile.get("indexes", []) if isinstance(row, dict)]
    validation.check(set(profile_index_kinds) == required_index_kinds, "Sealed profile index kinds differ from the complete index registry")
    validation.check(len(profile_index_kinds) == len(set(profile_index_kinds)), "Sealed profile repeats an index kind")
    index_coordinate_keys = coordinate_keys
    for index in profile.get("indexes", []):
        validation.check(index.get("status") == "ready", f"Sealed manifest contains non-ready {index.get('kind')} index")
        for key in index_coordinate_keys:
            validation.check(index.get(key) == coordinate[key], f"{index.get('kind')} index {key} differs from the sealed projection")
        validation.check(index.get("hashAlgorithm") == "sha256-jcs", f"{index.get('kind')} index declares no canonical hash algorithm")
        validation.check(index.get("contentHash") == digest(index, "contentHash"), f"{index.get('kind')} index contentHash mismatch")
        namespace_preimage = [index.get(key) for key in ("sourceId", "sourceVersion", "connectorId", "connectorVersion", "connectorCapabilityHash", "projectionId", "manifestVersion", "authorizationScopeId", "policyHash", "revocationEpoch", "kind", "version")]
        expected_namespace = hashlib.sha256(rfc8785.dumps(namespace_preimage)).hexdigest()
        validation.check(index.get("namespace") == expected_namespace, f"{index.get('kind')} index namespace is not bound to its coordinate")
        built_at = parse_time(index.get("builtAt"))
        if index_start is not None and index_end is not None and built_at is not None:
            validation.check(index_start <= built_at <= index_end, f"{index.get('kind')} index was built outside the build-indexes stage")
        index_summaries.append({key: index.get(key) for key in ("indexId", "kind", "version", "contentHash")})

    expected_summaries = sorted(index_summaries, key=lambda item: item["indexId"])
    actual_summaries = sorted(publication.get("indexes", []), key=lambda item: item.get("indexId", ""))
    validation.check(actual_summaries == expected_summaries, "Publication receipt indexes differ from the sealed profile manifest")
    publication_index_kinds = [row.get("kind") for row in publication.get("indexes", []) if isinstance(row, dict)]
    validation.check(set(publication_index_kinds) == required_index_kinds, "Publication receipt omits a required index kind")
    validation.check(len(publication_index_kinds) == len(set(publication_index_kinds)), "Publication receipt repeats an index kind")
    validation.check(publication.get("profileManifestId") == profile.get("manifestId"), "Publication receipt names a different profile manifest")
    validation.check(publication.get("profileContentHash") == profile.get("contentHash"), "Publication receipt profile hash differs from the manifest")
    validation.check(publication.get("capabilityManifestId") == capability.get("manifestId"), "Publication receipt names a different capability manifest")
    validation.check(publication.get("capabilityContentHash") == capability.get("contentHash"), "Publication receipt capability hash differs from the manifest")
    validation.check(publication.get("hashAlgorithm") == "sha256-jcs", "Publication receipt declares no canonical hash algorithm")
    publication_hash_input = {key: value for key, value in publication.items() if key not in {"receiptHash", "signature"}}
    expected_publication_hash = hashlib.sha256(rfc8785.dumps(publication_hash_input)).hexdigest()
    validation.check(publication.get("receiptHash") == expected_publication_hash, "Publication receipt hash mismatch")

    for name, generated_at in (("profile manifest", profile.get("generatedAt")), ("capability manifest", capability.get("generatedAt"))):
        generated = parse_time(generated_at)
        if manifest_start is not None and manifest_end is not None and generated is not None:
            validation.check(manifest_start <= generated <= manifest_end, f"{name} was generated outside the build-manifests stage")
    published_at = parse_time(publication.get("publishedAt"))
    if publish_start is not None and publish_end is not None and published_at is not None:
        validation.check(publish_start <= published_at <= publish_end, "Publication receipt time is outside the publish stage")

    run_coordinate = {key: run.get(key) for key in coordinate_keys}
    for record in bundle.get("records", []):
        validation.check(record.get("runId") == run.get("runId"), f"Evidence {record.get('evidenceId')} references a different run")
        for key in ("sourceId", "sourceVersion", "connectorId", "connectorVersion", "connectorCapabilityHash", "authorizationScopeId", "policyHash", "taxonomyVersion", "revocationEpoch"):
            validation.check(record.get(key) == run_coordinate[key], f"Evidence {record.get('evidenceId')} {key} differs from its run")
        validation.check(record.get("fencingToken") == run.get("fencingToken"), f"Evidence {record.get('evidenceId')} fencing token differs from its run")
        created = parse_time(record.get("createdAt"))
        cutoff = parse_time(coordinate["evidenceCutoff"])
        if created is not None and cutoff is not None:
            validation.check(created <= cutoff, f"Evidence {record.get('evidenceId')} was created after the projection cutoff")

    for key in ("runId", "sourceId", "sourceVersion", "connectorId", "connectorVersion", "connectorCapabilityHash", "authorizationScopeId", "policyHash", "fencingToken", "revocationEpoch"):
        validation.check(parser.get(key) == run.get(key), f"Parser execution {key} differs from its run")
    for key in ("sourceId", "sourceVersion", "connectorId", "connectorVersion", "connectorCapabilityHash", "authorizationScopeId", "policyHash", "revocationEpoch"):
        validation.check(model.get(key) == run.get(key), f"Model execution {key} differs from the profiling run")


def validate_index_registry(validation: Validation) -> None:
    registry = load_json("pipeline/index-registry.json", validation)
    index_schema = load_json("contracts/index-manifest.schema.json", validation)
    deletion_schema = load_json("contracts/deletion-receipt.schema.json", validation)
    if not all(isinstance(value, dict) for value in (registry, index_schema, deletion_schema)):
        return

    declared = [row for row in registry.get("indexKinds", []) if isinstance(row, dict)]
    registry_kinds = {row.get("id") for row in declared}
    schema_kinds = set(index_schema.get("properties", {}).get("kind", {}).get("enum", []))
    validation.check(registry_kinds == schema_kinds, "Index-manifest kinds differ from the index registry")

    store_kinds = set(
        deletion_schema.get("properties", {}).get("stores", {}).get("items", {})
        .get("properties", {}).get("storeKind", {}).get("enum", [])
    )
    expected_stores = {row.get("storeKind") for row in declared} | set(registry.get("nonIndexGovernedStores", []))
    validation.check(store_kinds == expected_stores, f"Lifecycle store kinds differ from the index registry: {sorted(store_kinds ^ expected_stores)}")

    required_fields = set(index_schema.get("required", []))
    for row in declared:
        kind = row.get("id")
        applicable = set(required_fields)
        for rule in index_schema.get("allOf", []):
            condition = rule.get("if", {}).get("properties", {}).get("kind", {})
            if condition.get("const") == kind or kind in (condition.get("enum") or []):
                applicable |= set(rule.get("then", {}).get("required", []))
        missing = set(row.get("requiredMetadata", [])) - applicable
        validation.check(not missing, f"Index kind {kind} declares metadata the contract does not require for it: {sorted(missing)}")


def validate_maturity_rank(validation: Validation) -> None:
    try:
        import yaml  # type: ignore[import-not-found]
        taxonomy = yaml.safe_load((ROOT / "taxonomies" / "evidence-kinds.yaml").read_text(encoding="utf-8"))
        evidence_schema = load_json("contracts/evidence-record.schema.json", validation)
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read the evidence taxonomy: {exc}")
        return
    if not isinstance(evidence_schema, dict):
        return

    ranks = taxonomy.get("maturityRank", {})
    validation.check(bool(ranks), "The evidence taxonomy declares no maturity rank")
    validation.check(len(set(ranks.values())) == len(ranks), "Maturity ranks are not distinct")
    validation.check(
        ranks.get("observed", 0) > ranks.get("inferred", 0),
        "A directly observed fact must outrank a generated hypothesis",
    )

    declared_states = {row.get("id") for row in taxonomy.get("maturityStates", []) if isinstance(row, dict)}
    schema_states = set(evidence_schema.get("properties", {}).get("maturity", {}).get("enum", []))
    validation.check(declared_states == schema_states, f"Taxonomy maturity states differ from the evidence contract: {sorted(declared_states ^ schema_states)}")
    validation.check(set(ranks) <= declared_states, "Maturity rank references an undeclared state")
    taxonomy_kinds = set(taxonomy.get("evidenceKinds", []))
    schema_kinds = set(evidence_schema.get("properties", {}).get("kind", {}).get("enum", []))
    validation.check(taxonomy_kinds == schema_kinds, f"Taxonomy evidence kinds differ from the evidence contract: {sorted(taxonomy_kinds ^ schema_kinds)}")
    taxonomy_outcomes = set(taxonomy.get("evaluationOutcomes", []))
    schema_outcomes = set(evidence_schema.get("properties", {}).get("outcome", {}).get("enum", []))
    validation.check(taxonomy_outcomes == schema_outcomes, f"Taxonomy outcomes differ from the evidence contract: {sorted(taxonomy_outcomes ^ schema_outcomes)}")

    api_text = (ROOT / "contracts" / "api.openapi.yaml").read_text(encoding="utf-8")
    match = re.search(r"minimumMaturity:.*?enum:\s*\[([^\]]+)\]", api_text, re.DOTALL)
    validation.check(match is not None, "The retrieval API declares no minimumMaturity enum")
    if match is not None:
        api_states = {item.strip() for item in match.group(1).split(",")}
        validation.check(api_states == set(ranks), f"Retrieval minimumMaturity differs from the ranked states: {sorted(api_states ^ set(ranks))}")

    retrieval_schema = load_json("contracts/retrieval-bundle.schema.json", validation)
    response_states = set()
    if isinstance(retrieval_schema, dict):
        response_states = set(
            retrieval_schema.get("properties", {}).get("items", {}).get("items", {})
            .get("properties", {}).get("maturity", {}).get("enum", [])
        )
    validation.check(bool(response_states), "The retrieval response declares no maturity enum")
    validation.check(
        response_states == set(ranks),
        f"Retrieval response maturity differs from the ranked states: {sorted(response_states ^ set(ranks))}",
    )


def validate_openapi_stage_enum(validation: Validation) -> None:
    stages = load_json("pipeline/stages.json", validation)
    if not isinstance(stages, dict):
        return
    canonical = [row.get("id") for row in stages.get("stages", []) if isinstance(row, dict)]
    api_text = (ROOT / "contracts" / "api.openapi.yaml").read_text(encoding="utf-8")
    match = re.search(r"fromStage:.*?enum:\s*\[([^\]]+)\]", api_text, re.DOTALL)
    validation.check(match is not None, "The run API does not constrain fromStage to canonical stage IDs")
    if match is not None:
        declared = [item.strip() for item in match.group(1).split(",")]
        validation.check(declared == canonical, "The run API fromStage enum differs from the canonical stage order")


def validate_execution_receipts(validation: Validation) -> None:
    """Parser usage must stay within its declared limits, and cache keys must be derivable."""
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
        return

    parser = load_json("examples/parser-execution.json", validation)
    budget_bundle = load_json("examples/execution-budget-bundle.json", validation)
    run = load_json("examples/profiling-run.json", validation)
    read_result = load_json("examples/read-execution-result.json", validation)
    if isinstance(parser, dict):
        limits = parser.get("limits", {})
        usage = parser.get("usage", {})
        try:
            import yaml  # type: ignore[import-not-found]
            policy_limits = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))["parserIsolation"]["limits"]
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Unable to read the parser-isolation policy: {exc}")
            policy_limits = {}
        validation.check(parser.get("limitsSource") == "policy", "Parser receipt does not declare its limits as policy-derived")
        validation.check(set(limits) == set(policy_limits), f"Parser receipt limits differ from the policy dimensions: {sorted(set(limits) ^ set(policy_limits))}")
        for key, ceiling in policy_limits.items():
            declared = limits.get(key)
            validation.check(
                declared is not None and declared <= ceiling,
                f"Parser receipt limit {key}={declared} exceeds the policy ceiling {ceiling}",
            )
        mapping = {key: key for key in limits}
        mapping["peakMemoryBytes"] = "memoryBytes"
        within_limits = True
        for usage_key, value in usage.items():
            limit_key = mapping.get(usage_key, usage_key)
            limit = limits.get(limit_key)
            validation.check(limit is not None, f"Parser usage {usage_key} has no declared limit")
            if limit is None:
                continue
            if value > limit:
                within_limits = False
            validation.check(
                value <= limit or parser.get("outcome") != "completed",
                f"Parser receipt reports completed while {usage_key} exceeds its limit",
            )
        validation.check(
            within_limits or parser.get("outcome") in {"partial", "blocked", "failed", "cancelled"},
            "Parser receipt exceeds a declared limit without a partial, blocked, failed, or cancelled outcome",
        )
        cleanup = parser.get("cleanup", {})
        validation.check(
            cleanup.get("completed") is True or bool(cleanup.get("cleanupFailureReasonCode")),
            "Parser receipt reports incomplete cleanup without a reason code",
        )
        if cleanup.get("completed") is True:
            validation.check(cleanup.get("residualArtifactCount") == 0, "Parser receipt claims complete cleanup while residual artifacts remain")
            validation.check(cleanup.get("cleanupFailureReasonCode") is None, "Parser receipt claims complete cleanup with a failure reason")

    model = load_json("examples/model-execution.json", validation)
    if isinstance(model, dict):
        admission = model.get("admission", {})
        cache = model.get("cache", {})
        try:
            import yaml  # type: ignore[import-not-found]
            model_policy = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))["modelAdmission"]
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Unable to read model-admission policy: {exc}")
            model_policy = {}

        def resolve_package_file(reference: Any, label: str) -> Path | None:
            relative = reference.removeprefix("package://") if isinstance(reference, str) and reference.startswith("package://") else ""
            path = (ROOT / relative).resolve()
            validation.check(bool(relative) and path.is_file() and ROOT.resolve() in path.parents, f"Model {label} does not resolve inside the package")
            return path if relative and path.is_file() and ROOT.resolve() in path.parents else None

        prompt_path = resolve_package_file(model.get("promptRef"), "prompt input")
        parameter_path = resolve_package_file(model.get("parameterSetRef"), "parameter input")
        redacted_input_path = resolve_package_file(model.get("redactedInputRef"), "redacted input")
        if prompt_path is not None:
            validation.check(model.get("promptSha256") == hashlib.sha256(prompt_path.read_bytes()).hexdigest(), "Model prompt byte hash mismatch")
        if parameter_path is not None:
            parameters = load_json(parameter_path.relative_to(ROOT).as_posix(), validation)
            if isinstance(parameters, dict):
                validation.check(model.get("parameterHash") == hashlib.sha256(rfc8785.dumps(parameters)).hexdigest(), "Model parameterHash is not derived from its parameter input")
        if redacted_input_path is not None:
            validation.check(model.get("redactedInputSha256") == hashlib.sha256(redacted_input_path.read_bytes()).hexdigest(), "Model redactedInputSha256 is not derived from exact redacted input bytes")
        classification = admission.get("inputClassification")
        validation.check(classification in model_policy.get("permittedInputClassifications", []), "Model admission uses a classification not permitted by policy")
        validation.check(classification not in model_policy.get("deniedInputClassifications", []), "Model admission uses a classification denied by policy")
        validation.check(cache.get("revocationEpoch") == model.get("revocationEpoch"), "Cache revocation epoch differs from the model execution")
        validation.check(admission.get("admittedProviderId") == model.get("providerId"), "Model admission provider differs from execution")
        validation.check(admission.get("admittedModelId") == model.get("modelId"), "Model admission model differs from execution")
        validation.check(admission.get("admittedModelVersion") == model.get("modelVersion"), "Model admission version differs from execution")
        validation.check(admission.get("admittedModelDeploymentHash") == model.get("modelDeploymentHash"), "Model admission deployment digest differs from execution")
        validation.check(
            cache.get("admissionPolicyHash") == admission.get("modelPolicyHash"),
            "Cache entry is not bound to the model-admission policy hash",
        )
        validation.check(
            cache.get("admissionDeploymentRegistrationId") == admission.get("deploymentRegistrationId"),
            "Cache entry is not bound to the admitted deployment",
        )
        decided_at = datetime.fromisoformat(admission["decidedAt"].replace("Z", "+00:00"))
        started_at = datetime.fromisoformat(model["startedAt"].replace("Z", "+00:00"))
        completed_at = datetime.fromisoformat(model["completedAt"].replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(cache["expiresAt"].replace("Z", "+00:00"))
        validation.check(decided_at <= started_at <= completed_at, "Model admission and execution timestamps are out of order")
        compatible_regions = model_policy.get("residencyCompatibility", {}).get(admission.get("sourceResidencyClass"), [])
        validation.check(admission.get("deploymentRegion") in compatible_regions, "Model deployment region is incompatible with source residency policy")
        validation.check(expires_at > completed_at, "Model cache expiry does not follow the producing execution")
        if cache.get("decision") == "hit":
            validation.check(expires_at > started_at, "Expired model cache entry was accepted as a hit")
        evidence_bundle = load_json("examples/evidence-bundle.json", validation)
        if isinstance(evidence_bundle, dict):
            requested_evidence_ids = set(model.get("inputEvidenceIds", []))
            evidence_by_id = {row.get("evidenceId"): row for row in evidence_bundle.get("records", []) if isinstance(row, dict)}
            validation.check(requested_evidence_ids <= set(evidence_by_id), "Model inputEvidenceIds contain missing evidence")
            evidence_bindings = sorted(
                ({"evidenceId": evidence_id, "recordHash": evidence_by_id[evidence_id].get("recordHash")} for evidence_id in requested_evidence_ids if evidence_id in evidence_by_id),
                key=lambda row: row["evidenceId"],
            )
            expected_evidence_set_hash = hashlib.sha256(rfc8785.dumps(evidence_bindings)).hexdigest()
            validation.check(model.get("evidenceSetHash") == expected_evidence_set_hash, "Model evidenceSetHash is not derived from referenced evidence records")
        preimage = [
            model.get("sourceId"),
            model.get("sourceVersion"),
            model.get("connectorId"),
            model.get("connectorVersion"),
            model.get("connectorCapabilityHash"),
            model.get("authorizationScopeId"),
            cache.get("revocationEpoch"),
            model.get("policyHash"),
            model.get("evidenceSetHash"),
            admission.get("modelPolicyHash"),
            admission.get("deploymentRegistrationId"),
            model.get("providerId"),
            model.get("modelId"),
            model.get("modelVersion"),
            model.get("modelDeploymentHash"),
            model.get("promptId"),
            model.get("promptVersion"),
            model.get("inputContractRef"),
            model.get("outputContractRef"),
            model.get("parameterHash"),
            model.get("redactedInputSha256"),
        ]
        expected = hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()
        validation.check(
            cache.get("keySha256") == expected,
            f"Cache keySha256 is not derivable from its declared preimage: expected {expected}",
        )
        namespace_preimage = [
            model.get("sourceId"),
            model.get("sourceVersion"),
            model.get("connectorId"),
            model.get("connectorVersion"),
            model.get("connectorCapabilityHash"),
            model.get("authorizationScopeId"),
            model.get("revocationEpoch"),
            model.get("policyHash"),
            admission.get("modelPolicyHash"),
            admission.get("deploymentRegistrationId"),
            model.get("providerId"),
            model.get("modelId"),
            model.get("modelVersion"),
            model.get("modelDeploymentHash"),
        ]
        expected_namespace = hashlib.sha256(rfc8785.dumps(namespace_preimage)).hexdigest()
        validation.check(cache.get("namespace") == expected_namespace, "Cache namespace is not bound to its source, scope, epoch, policy, admission, and model")

    if not all(isinstance(value, dict) for value in (budget_bundle, run, read_result, model)):
        return
    records = [row for row in budget_bundle.get("records", []) if isinstance(row, dict)]
    scopes = [row.get("scope") for row in records]
    required_scopes = {"connector-call", "model-call", "stage", "run", "prompt", "queue", "query", "traversal", "manifest"}
    validation.check(required_scopes <= set(scopes), f"Execution budget scopes omit required scopes: {sorted(required_scopes - set(scopes))}")
    operation_ids = [row.get("operationId") for row in records]
    validation.check(len(operation_ids) == len(set(operation_ids)), "Execution budget bundle contains a duplicate operation ID")
    validation.check(budget_bundle.get("runId") == run.get("runId"), "Execution budget bundle names another run")
    validation.check(budget_bundle.get("policyHash") == run.get("policyHash"), "Execution budget bundle policy differs from its run")
    try:
        import yaml  # type: ignore[import-not-found]
        operation_policy = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8")).get("operationBudgets", {})
        validation.check(set(operation_policy) == required_scopes, "Operation budget policy does not cover every required scope")
    except Exception as exc:  # noqa: BLE001
        operation_policy = {}
        validation.check(False, f"Unable to load operation budget policy: {exc}")
    try:
        captured_at = datetime.fromisoformat(budget_bundle["capturedAt"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        validation.check(False, f"Execution budget capturedAt is invalid: {exc}")
        captured_at = None
    for row in records:
        expected_policy = operation_policy.get(row.get("scope"), {})
        validation.check(
            {key: row.get(key) for key in ("limit", "unit", "cancellationCheckInterval")} == expected_policy,
            f"Execution budget {row.get('scope')} differs from policy",
        )
        validation.check(row.get("usage", 0) <= row.get("limit", -1), f"Execution budget {row.get('scope')} usage exceeds its limit")
        validation.check(0 < row.get("cancellationCheckInterval", 0) <= row.get("limit", 0), f"Execution budget {row.get('scope')} has an invalid cancellation interval")
        try:
            started = datetime.fromisoformat(row["startedAt"].replace("Z", "+00:00"))
            completed = datetime.fromisoformat(row["completedAt"].replace("Z", "+00:00"))
            cancelled = datetime.fromisoformat(row["cancelledAt"].replace("Z", "+00:00")) if row.get("cancelledAt") else None
            validation.check(started <= completed, f"Execution budget {row.get('scope')} completes before it starts")
            if captured_at is not None:
                validation.check(
                    started <= completed <= captured_at,
                    f"Execution budget {row.get('scope')} is not complete by bundle capturedAt",
                )
            if row.get("unit") == "milliseconds":
                elapsed_milliseconds = int((completed - started).total_seconds() * 1000)
                validation.check(row.get("usage") == elapsed_milliseconds, f"Execution budget {row.get('scope')} usage differs from elapsed milliseconds")
            validation.check(cancelled is None or started <= cancelled <= completed, f"Execution budget {row.get('scope')} cancellation time is invalid")
            validation.check((row.get("outcome") == "cancelled") == (cancelled is not None), f"Execution budget {row.get('scope')} cancellation outcome disagrees with cancelledAt")
            validation.check((row.get("outcome") in {"completed", "completed-partial"}) == (row.get("reasonCode") is None), f"Execution budget {row.get('scope')} reason code disagrees with outcome")
        except (KeyError, TypeError, ValueError) as exc:
            validation.check(False, f"Execution budget {row.get('scope')} contains invalid timestamps: {exc}")
    for scope in required_scopes:
        scope_rows = [row for row in records if row.get("scope") == scope]
        validation.check(
            sum(row.get("usage", 0) for row in scope_rows) <= operation_policy.get(scope, {}).get("limit", -1),
            f"Execution budget {scope} aggregate usage exceeds its policy limit",
        )
    expected_budget_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in budget_bundle.items() if key != "contentHash"})).hexdigest()
    validation.check(budget_bundle.get("contentHash") == expected_budget_hash, "Execution budget bundle content hash mismatch")
    by_scope = {scope: [row for row in records if row.get("scope") == scope] for scope in required_scopes}
    model_budget = next((row for row in by_scope.get("model-call", []) if row.get("operationId") == model.get("executionId")), {})
    validation.check(bool(model_budget), "Model-call budget names no record for the model execution")
    validation.check(model_budget.get("usage") == model.get("usage", {}).get("inputUnits", 0) + model.get("usage", {}).get("outputUnits", 0), "Model-call budget usage differs from model receipt")
    run_budget = next((row for row in by_scope.get("run", []) if row.get("operationId") == run.get("runId")), {})
    validation.check(run_budget.get("operationId") == run.get("runId") and run_budget.get("usage") == run.get("budget", {}).get("usage", {}).get("wallClockMilliseconds"), "Run budget receipt differs from run usage")
    query_budget = next((row for row in by_scope.get("query", []) if row.get("operationId") == read_result.get("operationId")), {})
    validation.check(query_budget.get("operationId") == read_result.get("operationId") and query_budget.get("usage") == read_result.get("receipt", {}).get("rowsReturned"), "Query budget receipt differs from read execution")


def validate_projection_privacy(validation: Validation) -> None:
    """Enforce privacy policy in the served projection, not only in source evidence."""
    try:
        import rfc8785  # type: ignore[import-not-found]
        import yaml  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        policy = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read privacy policy: {exc}")
        return
    profile = load_json("examples/profile-manifest.json", validation)
    capability = load_json("examples/capability-manifest.json", validation)
    retrieval = load_json("examples/retrieval-bundle.json", validation)
    read_result = load_json("examples/read-execution-result.json", validation)
    evidence_response = load_json("examples/evidence-response.json", validation)
    safety = load_json("examples/projection-safety-receipt.json", validation)
    fingerprint_set = load_json("examples/source-value-fingerprint-set.json", validation)
    publication = load_json("examples/publication-receipt.json", validation)
    if not all(isinstance(value, dict) for value in (profile, capability, retrieval, read_result, evidence_response, safety, fingerprint_set, publication)):
        return
    minimum_group_size = policy.get("privacy", {}).get("minimumGroupSize")
    validation.check(isinstance(minimum_group_size, int) and minimum_group_size > 0, "Privacy policy declares no positive minimum group size")
    if not isinstance(minimum_group_size, int):
        return

    machine_keys = {
        "signature", "publicKeyBase64", "contentHash", "payloadHash", "schemaHash",
        "policyHash", "methodSetHash", "connectorCapabilityHash", "validationPlanHash",
        "namespace", "sourceId", "projectionId", "manifestId", "profileManifestId",
        "capabilityManifestId", "receiptId", "evidenceId", "extensionId", "indexId",
        "relationshipId", "conceptId", "patternId", "traceId", "issuerKeyId",
    }
    def is_machine_value(key: str, value: str) -> bool:
        if (key in machine_keys or key.endswith("Hash")) and re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return True
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            pass
        if re.fullmatch(r"sha256:[a-fA-F0-9]{64}", value):
            return True
        if key in {"signature", "publicKeyBase64"}:
            try:
                decoded = base64.b64decode(value, validate=True)
                if len(decoded) in {32, 64}:
                    return True
            except ValueError:
                pass
        if detects_secret_like_input(value) or contains_direct_identifier(value):
            return False
        if key in machine_keys or key.endswith(("Hash", "Id", "Ids", "Ref", "Refs", "Version", "At", "Uri")):
            return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,499}", value) is not None
        return False

    active_text_limit = policy.get("agentResponses", {}).get("maximumTextCharacters")
    served_text_by_document: dict[str, list[str]] = {}

    def walk_served(value: Any, path: str, parent_key: str = "", text_values: list[str] | None = None) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk_served(child, f"{path}.{key}", key, text_values)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk_served(child, f"{path}[{index}]", parent_key, text_values)
        elif isinstance(value, str) and (
            path.startswith("readResult.rows")
            or re.search(r"\.sourceExtensions\[[0-9]+\]\.payload(?:\.|\[|$)", path) is not None
            or re.search(r"^evidenceResponse\.items\[[0-9]+\]\.(?:claim\.object|payload)(?:\.|\[|$)", path) is not None
            or not is_machine_value(parent_key, value)
        ):
            if text_values is not None:
                text_values.append(value)
            validation.check(isinstance(active_text_limit, int) and len(value) <= active_text_limit, f"Served content at {path} exceeds the response text limit")
            validation.check(not detects_secret_like_input(value), f"Served content at {path} contains secret-like material")
            validation.check(not contains_direct_identifier(value), f"Served content at {path} contains a direct identifier")

    for name, document in (("profile", profile), ("capability", capability), ("evidenceResponse", evidence_response), ("retrieval", retrieval), ("readResult", read_result)):
        text_values: list[str] = []
        walk_served(document, name, text_values=text_values)
        served_text_by_document[name] = text_values
        response_policy = document.get("responsePolicy", {})
        configured = policy.get("agentResponses", {})
        validation.check(
            response_policy.get("maximumSerializedBytes") == configured.get("maximumSerializedBytes"),
            f"{name} response byte limit differs from policy",
        )
        validation.check(
            response_policy.get("maximumTextCharacters") == configured.get("maximumTextCharacters"),
            f"{name} response text limit differs from policy",
        )
        validation.check(
            response_policy.get("defaultContentProvenance") == "source-derived",
            f"{name} response does not conservatively mark unmatched free text source-derived",
        )
        validation.check(
            len(rfc8785.dumps(document)) <= response_policy.get("maximumSerializedBytes", 0),
            f"{name} response exceeds its serialized byte budget",
        )
        service_patterns = response_policy.get("serviceGeneratedPathPatterns", [])
        source_patterns = response_policy.get("sourceDerivedPathPatterns", [])
        validation.check(len(service_patterns) == len(set(service_patterns)), f"{name} repeats service-generated provenance patterns")
        validation.check(len(source_patterns) == len(set(source_patterns)), f"{name} repeats source-derived provenance patterns")
        validation.check(set(service_patterns).isdisjoint(source_patterns), f"{name} provenance patterns conflict")

    validation.check(
        all(column.get("contentProvenance") in {"service-generated", "source-derived"} for column in read_result.get("columns", [])),
        "Read-result columns do not declare value provenance",
    )

    coordinate_keys = (
        "sourceId", "sourceVersion", "projectionId", "manifestVersion", "connectorId", "connectorVersion",
        "connectorCapabilityHash", "authorizationScopeId", "policyHash", "taxonomyVersion", "pipelineVersion",
        "methodSetHash", "evidenceCutoff", "revocationEpoch",
    )
    coordinate = {key: profile.get(key) for key in coordinate_keys}
    validation.check(safety.get("coordinate") == coordinate, "Projection-safety receipt coordinate differs from the served profile")
    validation.check(safety.get("runId") == publication.get("runId"), "Projection-safety receipt names another run")
    validation.check(safety.get("profileContentHash") == profile.get("contentHash"), "Projection-safety receipt profile hash differs")
    validation.check(safety.get("capabilityContentHash") == capability.get("contentHash"), "Projection-safety receipt capability hash differs")
    validation.check(publication.get("projectionSafetyReceiptId") == safety.get("receiptId"), "Publication names another projection-safety receipt")
    validation.check(publication.get("projectionSafetyReceiptHash") == safety.get("receiptHash"), "Publication projection-safety hash differs")
    validation.check(safety.get("sourceValueFingerprintCount", 0) > 0, "Projection-safety scan compared no source-value fingerprints")
    validation.check(safety.get("scannedTextFieldCount", 0) > 0, "Projection-safety scan inspected no served text")
    validation.check(safety.get("ordinaryRawValueCollisionCount") == 0, "Projection-safety scan found an ordinary raw source-value collision")
    validation.check(safety.get("secretCollisionCount") == 0, "Projection-safety scan found a secret collision")
    validation.check(safety.get("directIdentifierCollisionCount") == 0, "Projection-safety scan found a direct-identifier collision")
    try:
        validation.check(fingerprint_set.get("sourceId") == profile.get("sourceId"), "Source-value fingerprint set names another source")
        validation.check(fingerprint_set.get("sourceVersion") == profile.get("sourceVersion"), "Source-value fingerprint set names another source version")
        validation.check(fingerprint_set.get("authorizationScopeId") == profile.get("authorizationScopeId"), "Source-value fingerprint set names another authorization scope")
        fingerprint_preimage = {key: value for key, value in fingerprint_set.items() if key != "contentHash"}
        expected_fingerprint_content_hash = hashlib.sha256(rfc8785.dumps(fingerprint_preimage)).hexdigest()
        validation.check(fingerprint_set.get("contentHash") == expected_fingerprint_content_hash, "Source-value fingerprint-set content hash mismatch")
        fingerprints = sorted(fingerprint_set.get("fingerprints", []))
        validation.check(fingerprint_set.get("fingerprintCount") == len(fingerprints), "Source-value fingerprint count differs from its array")

        minimum_length = fingerprint_set.get("minimumFingerprintCharacterLength", 0)
        salt = fingerprint_set.get("conformanceSalt", "")

        def normalized_candidates(value: str) -> set[str]:
            normalized = unicodedata.normalize("NFKC", value).strip().casefold()
            candidates = {normalized} if len(normalized) >= minimum_length else set()
            candidates.update(
                token
                for token in re.findall(r"[^\W_]+", normalized, re.UNICODE)
                if len(token) >= minimum_length
            )
            return candidates

        def fingerprint(value: str) -> str:
            return hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()

        expected_fingerprints = sorted({
            fingerprint(candidate)
            for source_value in fingerprint_set.get("conformanceSourceValues", [])
            for candidate in normalized_candidates(source_value)
        })
        validation.check(fingerprints == expected_fingerprints, "Source-value fingerprints are not derivable from the conformance source set")
        expected_fingerprint_set_hash = hashlib.sha256(rfc8785.dumps(fingerprints)).hexdigest()
        validation.check(safety.get("sourceValueFingerprintSetId") == fingerprint_set.get("fingerprintSetId"), "Projection-safety receipt names another fingerprint set")
        validation.check(safety.get("sourceValueFingerprintSetHash") == expected_fingerprint_set_hash, "Projection-safety receipt fingerprint-set hash mismatch")
        validation.check(safety.get("sourceValueFingerprintCount") == len(fingerprints), "Projection-safety receipt fingerprint count mismatch")
        for field in ("fingerprintAlgorithm", "fingerprintGranularity", "normalizationVersion", "minimumFingerprintCharacterLength"):
            validation.check(safety.get(field) == fingerprint_set.get(field), f"Projection-safety receipt {field} differs from its fingerprint set")
        projection_texts = served_text_by_document.get("profile", []) + served_text_by_document.get("capability", [])
        collisions = sum(
            1
            for text in projection_texts
            if {fingerprint(candidate) for candidate in normalized_candidates(text)} & set(fingerprints)
        )
        secret_collisions = sum(1 for text in projection_texts if detects_secret_like_input(text))
        identifier_collisions = sum(1 for text in projection_texts if contains_direct_identifier(text))
        validation.check(safety.get("scannedTextFieldCount") == len(projection_texts), "Projection-safety receipt scanned-text count mismatch")
        validation.check(safety.get("ordinaryRawValueCollisionCount") == collisions, "Projection-safety receipt ordinary raw source-value collision count mismatch")
        validation.check(safety.get("secretCollisionCount") == secret_collisions, "Projection-safety receipt secret collision count mismatch")
        validation.check(safety.get("directIdentifierCollisionCount") == identifier_collisions, "Projection-safety receipt direct-identifier collision count mismatch")
        receipt_preimage = {key: value for key, value in safety.items() if key not in {"receiptHash", "signature"}}
        expected_receipt_hash = hashlib.sha256(rfc8785.dumps(receipt_preimage)).hexdigest()
        validation.check(safety.get("receiptHash") == expected_receipt_hash, "Projection-safety receipt hash mismatch")
        registry = load_trusted_issuers(
            ROOT,
            issuer_registry_path=TRUST_REGISTRY_PATH,
            expected_registry_sha256=TRUST_REGISTRY_SHA256,
            require_external=REQUIRE_EXTERNAL_TRUST,
        )
        issuer = next((row for row in registry.get("issuers", []) if row.get("issuerKeyId") == safety.get("issuerKeyId")), None)
        validation.check(issuer is not None and "projection-safety" in issuer.get("purposes", []), "Projection-safety receipt issuer is not authorized")
        if issuer is not None:
            scanned = datetime.fromisoformat(safety["scannedAt"].replace("Z", "+00:00"))
            published = datetime.fromisoformat(publication["publishedAt"].replace("Z", "+00:00"))
            valid_from = datetime.fromisoformat(issuer["validFrom"].replace("Z", "+00:00"))
            valid_until = datetime.fromisoformat(issuer["validUntil"].replace("Z", "+00:00"))
            validation.check(valid_from <= scanned < valid_until, "Projection-safety receipt was signed outside issuer validity")
            validation.check(scanned <= published, "Projection was published before its content-safety scan")
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(issuer.get("publicKeyBase64", ""), validate=True))
            public_key.verify(base64.b64decode(safety.get("signature", ""), validate=True), bytes.fromhex(safety.get("receiptHash", "")))
            validation.check(True, "Projection-safety receipt signature verified")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Projection-safety receipt verification failed: {exc}")

    for asset in profile.get("assets", []):
        asset_id = asset.get("assetId")
        handling = asset.get("dataHandling", {})
        validation.check(handling.get("containsRawSourceValues") is False, f"Asset {asset_id} is not declared raw-value-free")
        validation.check((handling.get("minimumGroupSizeApplied") or 0) >= minimum_group_size, f"Asset {asset_id} applies a group size below policy")
        for field in asset.get("fields", []):
            field_id = f"{asset_id}.{field.get('path')}"
            field_handling = field.get("dataHandling", {})
            validation.check(field_handling.get("containsRawSourceValues") is False, f"Field {field_id} is not declared raw-value-free")
            validation.check((field_handling.get("minimumGroupSizeApplied") or 0) >= minimum_group_size, f"Field {field_id} applies a group size below policy")
            statistics = field.get("statistics", {})
            if statistics:
                validation.check((statistics.get("minimumGroupSizeApplied") or 0) >= minimum_group_size, f"Field {field_id} statistics apply a group size below policy")
                validation.check((statistics.get("count") or 0) >= minimum_group_size, f"Field {field_id} publishes statistics for a sub-threshold population")

    for extension in profile.get("sourceExtensions", []):
        validation.check(extension.get("sourceId") == profile.get("sourceId"), f"Extension {extension.get('extensionId')} source differs from the profile")
        validation.check(extension.get("sourceVersion") == profile.get("sourceVersion"), f"Extension {extension.get('extensionId')} version differs from the profile")
        validation.check(extension.get("connectorId") == profile.get("connectorId"), f"Extension {extension.get('extensionId')} connector differs from the profile")
        validation.check(extension.get("connectorVersion") == profile.get("connectorVersion"), f"Extension {extension.get('extensionId')} connector version differs from the profile")
        validation.check(extension.get("connectorCapabilityHash") == profile.get("connectorCapabilityHash"), f"Extension {extension.get('extensionId')} connector capability hash differs from the profile")
        validation.check(extension.get("authorizationScopeId") == profile.get("authorizationScopeId"), f"Extension {extension.get('extensionId')} scope differs from the profile")
        validation.check(extension.get("revocationEpoch") == profile.get("revocationEpoch"), f"Extension {extension.get('extensionId')} epoch differs from the profile")
        validation.check(extension.get("policyHash") == profile.get("policyHash"), f"Extension {extension.get('extensionId')} policy differs from the profile")

    registry = load_json("config/extension-schema-registry.json", validation)
    if isinstance(registry, dict):
        registrations = [row for row in registry.get("schemas", []) if isinstance(row, dict)]
        keys = [(row.get("schemaId"), row.get("schemaVersion")) for row in registrations]
        validation.check(len(keys) == len(set(keys)), "Extension schema registry contains duplicate ID/version pairs")
        by_key = {key: row for key, row in zip(keys, registrations)}
        for extension in profile.get("sourceExtensions", []):
            key = (extension.get("payloadSchemaId"), extension.get("payloadSchemaVersion"))
            registration = by_key.get(key)
            validation.check(registration is not None, f"Extension {extension.get('extensionId')} uses an unregistered payload schema")
            if registration is None:
                continue
            schema_path = ROOT / registration.get("schemaPath", "")
            validation.check(schema_path.is_file(), f"Extension schema {key} does not resolve")
            if not schema_path.is_file():
                continue
            schema = load_json(registration["schemaPath"], validation)
            if not isinstance(schema, dict):
                continue
            expected_schema_hash = hashlib.sha256(rfc8785.dumps(schema)).hexdigest()
            validation.check(registration.get("schemaHash") == expected_schema_hash, f"Extension schema registry hash mismatch for {key}")
            validation.check(extension.get("payloadSchemaHash") == expected_schema_hash, f"Extension {extension.get('extensionId')} payload schema hash mismatch")
            validation.check(extension.get("sourceKind") in registration.get("allowedSourceKinds", []), f"Extension {extension.get('extensionId')} schema is not allowed for its source kind")
            errors: list[str] = []
            validate_schema(extension.get("payload"), schema, schema, "$", errors, schema_path)
            validation.check(not errors, f"Extension {extension.get('extensionId')} payload violates its registered schema: {'; '.join(errors)}")


def validate_read_plan_bindings(validation: Validation) -> None:
    """Typed plans must declare every parameter they reference, and receipts must bind to the plan."""
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
        return

    plan = load_json("examples/read-plan.json", validation)
    receipt = load_json("examples/read-plan-validation-receipt.json", validation)
    context = load_json("examples/read-plan-validation-context.json", validation)
    if not all(isinstance(value, dict) for value in (plan, receipt, context)):
        return

    declared = {item.get("name") for item in plan.get("parameters", []) if isinstance(item, dict)}
    validation.check(len(declared) == len(plan.get("parameters", [])), "Read plan declares duplicate parameter names")
    supplied = context.get("parameters", {})
    validation.check(isinstance(supplied, dict), "Read-plan validation context parameters are not an object")
    if not isinstance(supplied, dict):
        supplied = {}
    validation.check(set(supplied) <= declared, f"Read-plan validation context supplies undeclared parameters: {sorted(set(supplied) - declared)}")

    def type_matches(value: Any, parameter_type: str) -> bool:
        if parameter_type == "string":
            return isinstance(value, str)
        if parameter_type == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if parameter_type == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        if parameter_type == "boolean":
            return isinstance(value, bool)
        if parameter_type == "date-time":
            if not isinstance(value, str):
                return False
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                return parsed.tzinfo is not None
            except ValueError:
                return False
        if parameter_type == "string-array":
            return isinstance(value, list) and all(isinstance(item, str) for item in value)
        return False

    for parameter in plan.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        name = parameter.get("name")
        present = name in supplied
        validation.check(present or not parameter.get("required"), f"Required read-plan parameter {name} is missing")
        if not present:
            continue
        value = supplied[name]
        matches = type_matches(value, parameter.get("type"))
        validation.check(matches, f"Read-plan parameter {name} does not match declared type {parameter.get('type')}")
        if not matches:
            continue
        maximum_length = parameter.get("maximumLength")
        if isinstance(maximum_length, int):
            values = value if isinstance(value, list) else [value]
            validation.check(all(not isinstance(item, str) or len(item) <= maximum_length for item in values), f"Read-plan parameter {name} exceeds maximumLength")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = parameter.get("minimum")
            maximum = parameter.get("maximum")
            validation.check(minimum is None or value >= minimum, f"Read-plan parameter {name} is below minimum")
            validation.check(maximum is None or value <= maximum, f"Read-plan parameter {name} exceeds maximum")
        allowed = parameter.get("allowedValues", [])
        if allowed:
            values = value if isinstance(value, list) else [value]
            validation.check(all(item in allowed for item in values), f"Read-plan parameter {name} contains a value outside allowedValues")

    referenced: list[str] = []
    for operation in plan.get("operations", []):
        if not isinstance(operation, dict):
            continue
        for key, value in operation.items():
            if key == "parameterBindings" and isinstance(value, dict):
                referenced.extend(
                    binding.get("parameterRef")
                    for binding in value.values()
                    if isinstance(binding, dict)
                )
            elif key.endswith("ParameterRef") and isinstance(value, str):
                referenced.append(value)
        for filter_row in operation.get("filters", []):
            if not isinstance(filter_row, dict):
                continue
            reference = filter_row.get("parameterRef")
            operator = filter_row.get("operator")
            if operator in {"is-null", "is-not-null"}:
                validation.check(reference is None, f"Read-plan filter on {filter_row.get('path')} binds a parameter to a null-check operator")
            else:
                validation.check(isinstance(reference, str), f"Read-plan filter on {filter_row.get('path')} has no parameter binding")
                if isinstance(reference, str):
                    referenced.append(reference)

    for reference in referenced:
        validation.check(reference in declared, f"Read plan references undeclared parameter {reference}")

    validation.check(receipt.get("planId") == plan.get("planId"), "Validation receipt is not bound to the example plan")
    validation.check(receipt.get("hashAlgorithm") == "sha256-jcs", "Validation receipt declares no canonical hash algorithm")

    plan_preimage = {key: value for key, value in plan.items() if key != "planId"}
    expected_plan_hash = hashlib.sha256(rfc8785.dumps(plan_preimage)).hexdigest()
    expected_parameter_schema_hash = hashlib.sha256(rfc8785.dumps(plan.get("parameters", []))).hexdigest()
    validation.check(receipt.get("planHash") == expected_plan_hash, f"Receipt planHash mismatch: expected {expected_plan_hash}")
    validation.check(
        receipt.get("parameterSchemaHash") == expected_parameter_schema_hash,
        f"Receipt parameterSchemaHash mismatch: expected {expected_parameter_schema_hash}",
    )
    expected_parameter_values_hash = hashlib.sha256(rfc8785.dumps(context.get("parameters", {}))).hexdigest()
    caller = context.get("validatedCaller", {})
    subject_hashing = context.get("subjectHashing", {})
    expected_caller_hash = hashlib.sha256(
        rfc8785.dumps(["caller-subject-v1", subject_hashing.get("deploymentSalt"), caller.get("tenantId"), caller.get("subjectId")])
    ).hexdigest()
    validation.check(receipt.get("parameterValuesHash") == expected_parameter_values_hash, f"Receipt parameterValuesHash mismatch: expected {expected_parameter_values_hash}")
    validation.check(receipt.get("callerSubjectHash") == expected_caller_hash, f"Receipt callerSubjectHash mismatch: expected {expected_caller_hash}")
    validation.check(receipt.get("subjectHashSaltId") == subject_hashing.get("saltId"), "Receipt subject-hash salt identifier differs from verifier context")
    validation.check(receipt.get("delegationChainHash") == caller.get("delegationChainHash"), "Receipt delegation chain differs from the validated caller context")
    validation.check(receipt.get("authorizationScopeId") == context.get("validatedCaller", {}).get("authorizationScopeId"), "Receipt scope differs from the validated caller context")
    validation.check(plan.get("requestedSourceVersion") == receipt.get("sourceVersion"), "Read plan requested source version differs from the authorized projection")
    validation.check(plan.get("requestedManifestVersion") == receipt.get("manifestVersion"), "Read plan requested manifest version differs from the authorized projection")
    validation.check(receipt.get("valid") is True, "Read-plan validation receipt is not valid for execution")
    try:
        issued = datetime.fromisoformat(receipt["issuedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(receipt["expiresAt"].replace("Z", "+00:00"))
        validation.check(issued < expires, "Read-plan validation receipt does not expire after issuance")
    except (KeyError, TypeError, ValueError) as exc:
        validation.check(False, f"Read-plan validation receipt has invalid validity timestamps: {exc}")
    limits = plan.get("limits", {})
    estimated = receipt.get("estimatedCost", {})
    try:
        import yaml  # type: ignore[import-not-found]
        policy_limits = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8")).get("readExecution", {})
        validation.check(0 < limits.get("maximumRows", 0) <= policy_limits.get("maximumRows", 0), "Read-plan maximumRows exceeds the policy ceiling")
        validation.check(0 < limits.get("maximumBytes", 0) <= policy_limits.get("maximumBytes", 0), "Read-plan maximumBytes exceeds the policy ceiling")
        validation.check(0 < limits.get("timeoutSeconds", 0) * 1000 <= policy_limits.get("maximumDurationMilliseconds", 0), "Read-plan timeout exceeds the policy ceiling")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to validate read-execution policy ceilings: {exc}")
    validation.check(0 < estimated.get("maximumRows", 0) <= limits.get("maximumRows", 0), "Read-plan receipt row limit is outside the validated plan limit")
    validation.check(0 < estimated.get("maximumBytes", 0) <= limits.get("maximumBytes", 0), "Read-plan receipt byte limit is outside the validated plan limit")
    validation.check(0 < estimated.get("maximumDurationMilliseconds", 0) <= limits.get("timeoutSeconds", 0) * 1000, "Read-plan receipt duration limit is outside the validated plan timeout")

    integrity_preimage = {key: value for key, value in receipt.items() if key not in {"receiptIntegrityHash", "signature"}}
    expected_integrity = hashlib.sha256(rfc8785.dumps(integrity_preimage)).hexdigest()
    validation.check(
        receipt.get("receiptIntegrityHash") == expected_integrity,
        f"Receipt receiptIntegrityHash mismatch: expected {expected_integrity}",
    )


def validate_api_receipts(validation: Validation) -> None:
    """Validate idempotent write receipts and exact bounded-read accounting."""
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
        return

    context = load_json("examples/read-plan-validation-context.json", validation)
    cancellation_request = load_json("examples/cancellation-request.json", validation)
    cancellation = load_json("examples/cancellation-receipt.json", validation)
    feedback_request = load_json("examples/feedback-request.json", validation)
    feedback = load_json("examples/feedback-receipt.json", validation)
    read_receipt = load_json("examples/read-plan-validation-receipt.json", validation)
    read_result = load_json("examples/read-execution-result.json", validation)
    read_plan = load_json("examples/read-plan.json", validation)
    publication = load_json("examples/publication-receipt.json", validation)
    evidence = load_json("examples/evidence-bundle.json", validation)
    values = (context, cancellation_request, cancellation, feedback_request, feedback, read_receipt, read_result, read_plan, publication, evidence)
    if not all(isinstance(value, dict) for value in values):
        return

    caller = context.get("validatedCaller", {})
    subject_hashing = context.get("subjectHashing", {})
    caller_hash = hashlib.sha256(
        rfc8785.dumps(["caller-subject-v1", subject_hashing.get("deploymentSalt"), caller.get("tenantId"), caller.get("subjectId")])
    ).hexdigest()

    def validate_write_receipt(name: str, request: dict[str, Any], receipt: dict[str, Any]) -> None:
        expected_request_hash = hashlib.sha256(rfc8785.dumps(request)).hexdigest()
        expected_idempotency_hash = hashlib.sha256(rfc8785.dumps(request.get("idempotencyKey"))).hexdigest()
        expected_receipt_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in receipt.items() if key != "receiptHash"})).hexdigest()
        validation.check(receipt.get("actorSubjectHash") == caller_hash, f"{name} actor binding differs from the validated caller")
        validation.check(receipt.get("subjectHashSaltId") == subject_hashing.get("saltId"), f"{name} subject-hash salt identifier differs from verifier context")
        validation.check(receipt.get("requestHash") == expected_request_hash, f"{name} requestHash mismatch")
        validation.check(receipt.get("idempotencyKeyHash") == expected_idempotency_hash, f"{name} idempotencyKeyHash mismatch")
        validation.check(receipt.get("hashAlgorithm") == "sha256-jcs", f"{name} declares no canonical hash algorithm")
        validation.check(receipt.get("receiptHash") == expected_receipt_hash, f"{name} receiptHash mismatch")

    validate_write_receipt("Cancellation receipt", cancellation_request, cancellation)
    validation.check(cancellation.get("runId") == cancellation_request.get("runId"), "Cancellation receipt names a different run")
    validate_write_receipt("Feedback receipt", feedback_request, feedback)
    validation.check(feedback.get("reviewedEvidenceId") == feedback_request.get("reviewedEvidenceId"), "Feedback receipt names different reviewed evidence")
    validation.check(feedback.get("decision") == feedback_request.get("decision"), "Feedback receipt decision differs from the request")
    evidence_by_id = {record.get("evidenceId"): record for record in evidence.get("records", []) if isinstance(record, dict)}
    reviewed = evidence_by_id.get(feedback.get("reviewedEvidenceId"))
    validation.check(reviewed is not None, "Feedback receipt refers to missing reviewed evidence")
    if reviewed is not None:
        validation.check(feedback_request.get("evidenceVersionHash") == reviewed.get("recordHash"), "Feedback request reviewed a different evidence version")

    validation.check(read_result.get("validationReceiptId") == read_receipt.get("receiptId"), "Read result names a different validation receipt")
    validation.check(read_result.get("planId") == read_receipt.get("planId"), "Read result names a different plan")
    validation.check(read_result.get("planHash") == read_receipt.get("planHash"), "Read result plan hash differs from validation")
    validation.check(read_result.get("parameterValuesHash") == read_receipt.get("parameterValuesHash"), "Read result parameters differ from validation")
    validation.check(read_result.get("coordinate") == publication.get("coordinate"), "Read result coordinate differs from the published projection")
    receipt_coordinate = {
        key: read_receipt.get(key)
        for key in (
            "sourceId", "sourceVersion", "projectionId", "manifestVersion", "connectorId",
            "connectorVersion", "connectorCapabilityHash", "authorizationScopeId", "policyHash",
            "taxonomyVersion", "pipelineVersion", "methodSetHash", "evidenceCutoff", "revocationEpoch",
        )
    }
    validation.check(read_result.get("coordinate") == receipt_coordinate, "Read result coordinate differs from its validation receipt")
    validation.check(read_receipt.get("valid") is True, "Read execution used a validation receipt whose decision is invalid")
    try:
        issued = datetime.fromisoformat(read_receipt["issuedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(read_receipt["expiresAt"].replace("Z", "+00:00"))
        executed = datetime.fromisoformat(read_result["executedAt"].replace("Z", "+00:00"))
        validation.check(issued <= executed < expires, "Read execution occurred outside the validation receipt window")
    except (KeyError, TypeError, ValueError) as exc:
        validation.check(False, f"Read execution or receipt has invalid validity timestamps: {exc}")
    operations = read_plan.get("operations", [])
    validation.check(len(operations) == 1, "Read result cannot bind to a plan with other than one operation")
    if len(operations) == 1:
        operation = operations[0]
        for key in ("operationId", "operation"):
            validation.check(read_result.get(key) == operation.get(key), f"Read result {key} differs from the validated operation")
        expected_target = operation.get("assetId") or operation.get("sourceOperationId") or operation.get("eventTypeId")
        validation.check(read_result.get("targetId") == expected_target, "Read result targetId differs from the validated operation")
        expected_operation_hash = hashlib.sha256(rfc8785.dumps(operation)).hexdigest()
        validation.check(read_result.get("operationHash") == expected_operation_hash, "Read result operationHash differs from the validated operation")
        validation.check(read_result.get("resultShape") == "bounded-tabular-normalization", "Read result does not declare its normalized result shape")
        if operation.get("operation") == "tabular-query":
            column_names = [column.get("name") for column in read_result.get("columns", [])]
            validation.check(column_names == operation.get("projection", []), "Read result columns differ from the operation projection")
            validation.check(len(column_names) == len(set(column_names)), "Read result contains duplicate column names")
            for row in read_result.get("rows", []):
                validation.check(set(row) == set(column_names), "Read result row shape differs from the declared columns")
    rows = read_result.get("rows", [])
    payload = {"columns": read_result.get("columns", []), "rows": rows}
    validation.check(read_result.get("receipt", {}).get("rowsReturned") == len(rows), "Read result row count does not match its payload")
    validation.check(read_result.get("receipt", {}).get("bytesReturned") == len(rfc8785.dumps(payload)), "Read result byte count does not match its payload")
    execution_receipt = read_result.get("receipt", {})
    estimated = read_receipt.get("estimatedCost", {})
    validation.check(execution_receipt.get("rowsReturned", 0) <= estimated.get("maximumRows", -1), "Read execution exceeded the validated row limit")
    validation.check(execution_receipt.get("bytesReturned", 0) <= estimated.get("maximumBytes", -1), "Read execution exceeded the validated byte limit")
    validation.check(execution_receipt.get("durationMilliseconds", 0) <= estimated.get("maximumDurationMilliseconds", -1), "Read execution exceeded the validated duration limit")
    expected_result_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in read_result.items() if key != "resultHash"})).hexdigest()
    validation.check(read_result.get("hashAlgorithm") == "sha256-jcs", "Read result declares no canonical hash algorithm")
    validation.check(read_result.get("resultHash") == expected_result_hash, "Read result hash mismatch")


def validate_retrieval_bundle(validation: Validation) -> None:
    """Retrieval coverage and provenance must reconcile to sealed, authorized evidence."""
    bundle = load_json("examples/retrieval-bundle.json", validation)
    evidence = load_json("examples/evidence-bundle.json", validation)
    publication = load_json("examples/publication-receipt.json", validation)
    if not all(isinstance(value, dict) for value in (bundle, evidence, publication)):
        return

    coordinate = publication.get("coordinate", {})
    validation.check(bundle.get("coordinate") == coordinate, "Retrieval bundle coordinate differs from the published projection")
    bundle_coordinate = bundle.get("coordinate", {})

    items = bundle.get("items", [])
    coverage = bundle.get("coverageReceipt", {})
    omitted = coverage.get("omittedBySection", {})
    validation.check(set(omitted) == {"items", "caveats", "conflicts"}, "Retrieval omission accounting uses an undeclared or missing section")
    omitted_total = sum(value for value in omitted.values() if isinstance(value, int))
    validation.check(coverage.get("returnedItems") == len(items), "Retrieval returnedItems does not match the item payload")
    validation.check(
        coverage.get("authorizedCandidatesConsidered") == len(items) + omitted.get("items", 0),
        "Retrieval candidate accounting does not reconcile returned and omitted items",
    )
    validation.check(coverage.get("returnedCaveats") == len(bundle.get("caveats", [])), "Retrieval returnedCaveats does not match the caveat payload")
    validation.check(coverage.get("caveatsConsidered") == len(bundle.get("caveats", [])) + omitted.get("caveats", 0), "Retrieval caveat accounting does not reconcile")
    validation.check(coverage.get("returnedConflicts") == len(bundle.get("conflicts", [])), "Retrieval returnedConflicts does not match the conflict payload")
    validation.check(coverage.get("conflictsConsidered") == len(bundle.get("conflicts", [])) + omitted.get("conflicts", 0), "Retrieval conflict accounting does not reconcile")
    validation.check(coverage.get("truncated") == (omitted_total > 0), "Retrieval truncation flag disagrees with omitted section counts")
    validation.check(bool(coverage.get("reason")) == bool(coverage.get("truncated")), "Retrieval truncation reason disagrees with truncation state")

    evidence_by_id = {
        record.get("evidenceId"): record
        for record in evidence.get("records", [])
        if isinstance(record, dict)
    }

    def validate_refs(owner: str, refs: list[Any]) -> None:
        for evidence_id in refs:
            record = evidence_by_id.get(evidence_id)
            validation.check(record is not None, f"{owner} cites missing evidence {evidence_id}")
            if record is None:
                continue
            validation.check(record.get("sourceId") == bundle_coordinate.get("sourceId"), f"{owner} cites evidence from another source")
            validation.check(record.get("sourceVersion") == bundle_coordinate.get("sourceVersion"), f"{owner} cites evidence from another source version")
            validation.check(record.get("authorizationScopeId") == bundle_coordinate.get("authorizationScopeId"), f"{owner} cites evidence from another authorization scope")
            validation.check(record.get("policyHash") == bundle_coordinate.get("policyHash"), f"{owner} cites evidence under another policy")
            validation.check(record.get("revocationEpoch") == bundle_coordinate.get("revocationEpoch"), f"{owner} cites evidence from another revocation epoch")

    for index, item in enumerate(items):
        validate_refs(f"Retrieval item {index}", item.get("evidenceRefs", []) + item.get("counterEvidenceRefs", []))
    for index, caveat in enumerate(bundle.get("caveats", [])):
        refs = caveat.get("evidenceRefs", [])
        validation.check(bool(refs), f"Retrieval caveat {index} cites no evidence")
        validate_refs(f"Retrieval caveat {index}", refs)
    for index, conflict in enumerate(bundle.get("conflicts", [])):
        supporting = conflict.get("supportingEvidenceRefs", [])
        counter = conflict.get("counterEvidenceRefs", [])
        validation.check(bool(supporting), f"Retrieval conflict {index} cites no supporting evidence")
        validation.check(bool(counter), f"Retrieval conflict {index} cites no counter-evidence")
        validation.check(set(supporting).isdisjoint(counter), f"Retrieval conflict {index} uses the same evidence on both sides")
        validate_refs(f"Retrieval conflict {index}", supporting + counter)


def validate_lifecycle_inventory(validation: Validation) -> None:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        validation.check(False, f"Lifecycle signature dependency missing ({exc})")
        return
    receipt = load_json("examples/deletion-receipt.json", validation)
    schema = load_json("contracts/deletion-receipt.schema.json", validation)
    manifest_uri = receipt.get("inventoryManifestUri", "") if isinstance(receipt, dict) else ""
    manifest_path = (ROOT / manifest_uri.removeprefix("package://")).resolve() if manifest_uri.startswith("package://") else None
    validation.check(manifest_path is not None and manifest_path.is_file() and ROOT.resolve() in manifest_path.parents, "Lifecycle inventory manifest does not resolve inside the package")
    inventory_manifest = load_json(manifest_path.relative_to(ROOT).as_posix(), validation) if manifest_path is not None and manifest_path.is_file() and ROOT.resolve() in manifest_path.parents else None
    if not all(isinstance(value, dict) for value in (receipt, schema, inventory_manifest)):
        return

    try:
        import yaml  # type: ignore[import-not-found]
        policy = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))
        inventory_limits = policy["retention"]["deletionInventory"]
        maximum_page_bytes = policy["validation"]["maximumArtifactBytes"]
        inventory_documents = {"active": inventory_manifest}
        for name, inventory_document in inventory_documents.items():
            if not isinstance(inventory_document, dict):
                continue
            validation.check(inventory_document.get("artifactCount", -1) <= inventory_limits["maximumDeletionInventoryEntries"], f"Lifecycle {name} inventory artifact count exceeds policy maximumDeletionInventoryEntries")
            validation.check(len(inventory_document.get("pages", [])) <= inventory_limits["maximumPages"], f"Lifecycle {name} inventory page count exceeds policy maximum")
            validation.check(all(page.get("entryCount", -1) <= inventory_limits["maximumEntriesPerPage"] for page in inventory_document.get("pages", [])), f"Lifecycle {name} inventory page entry count exceeds policy maximum")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read deletion inventory policy limits: {exc}")

    store_kinds = set(
        schema.get("properties", {}).get("stores", {}).get("items", {})
        .get("properties", {}).get("storeKind", {}).get("enum", [])
    )
    validation.check(bool(store_kinds), "The lifecycle contract declares no governed store kinds")
    try:
        import rfc8785  # type: ignore[import-not-found]
        manifest_content_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        validation.check(receipt.get("inventoryManifestId") == inventory_manifest.get("inventoryId"), "Lifecycle receipt names another inventory manifest")
        validation.check(receipt.get("inventoryManifestContentHash") == manifest_content_hash, "Lifecycle inventory manifest byte hash mismatch")
        expected_manifest_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in inventory_manifest.items() if key != "contentHash"})).hexdigest()
        validation.check(inventory_manifest.get("contentHash") == expected_manifest_hash, "Lifecycle inventory manifest content hash mismatch")
        inventory_preimage = {
            "inventoryVersion": receipt.get("inventoryVersion"),
            "inventoryManifestId": inventory_manifest.get("inventoryId"),
            "inventoryManifestContentHash": manifest_content_hash,
            "storeCounts": inventory_manifest.get("storeCounts"),
        }
        expected_inventory_hash = hashlib.sha256(rfc8785.dumps(inventory_preimage)).hexdigest()
        validation.check(receipt.get("inventoryHash") == expected_inventory_hash, "Lifecycle receipt inventory hash is not derivable from the governed store inventory")
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
    if receipt.get("action") not in {"delete-derived-data", "delete-source-registration"}:
        return

    stores = [row for row in receipt.get("stores", []) if isinstance(row, dict)]
    present = [row.get("storeKind") for row in stores]
    validation.check(set(present) == store_kinds, f"Lifecycle receipt omits governed stores: {sorted(store_kinds - set(present))}")
    validation.check(len(present) == len(set(present)), "Lifecycle receipt repeats a store kind instead of covering the inventory")

    pages = inventory_manifest.get("pages", [])
    validation.check([row.get("ordinal") for row in pages] == list(range(len(pages))), "Lifecycle inventory page ordinals are not contiguous")
    all_entries: list[dict[str, Any]] = []
    for page in pages:
        page_uri = page.get("pageUri", "")
        if page_uri.startswith("artifact://"):
            validation.check(False, "Active lifecycle artifact page requires an explicit immutable resolver and independent byte pin")
            continue
        page_path = (ROOT / page_uri.removeprefix("package://")).resolve() if page_uri.startswith("package://") else None
        validation.check(page_path is not None and page_path.is_file() and ROOT.resolve() in page_path.parents, "Lifecycle inventory page does not resolve inside the package")
        if page_path is None or not page_path.is_file() or ROOT.resolve() not in page_path.parents:
            continue
        page_size = page_path.stat().st_size
        validation.check(
            page_size <= maximum_page_bytes,
            f"Lifecycle inventory page exceeds maximum validation artifact bytes ({page_size} > {maximum_page_bytes})",
        )
        if page_size > maximum_page_bytes:
            continue
        page_document = load_json(page_path.relative_to(ROOT).as_posix(), validation)
        if not isinstance(page_document, dict):
            continue
        validation.check(page.get("pageContentHash") == hashlib.sha256(page_path.read_bytes()).hexdigest(), "Lifecycle inventory page byte hash mismatch")
        validation.check(page_document.get("inventoryId") == inventory_manifest.get("inventoryId") and page_document.get("ordinal") == page.get("ordinal"), "Lifecycle inventory page binding differs")
        expected_page_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in page_document.items() if key != "contentHash"})).hexdigest()
        validation.check(page_document.get("contentHash") == expected_page_hash, "Lifecycle inventory page content hash mismatch")
        entries = [entry for entry in page_document.get("entries", []) if isinstance(entry, dict)]
        validation.check(page.get("entryCount") == len(entries), "Lifecycle inventory page entry count mismatch")
        all_entries.extend(entries)
    entry_keys = [(entry.get("storeKind"), entry.get("artifactId")) for entry in all_entries]
    validation.check(len(entry_keys) == len(set(entry_keys)), "Lifecycle inventory contains duplicate store/artifact entries")
    all_entries.sort(key=lambda entry: (entry.get("storeKind", ""), entry.get("artifactId", "")))
    validation.check(inventory_manifest.get("artifactCount") == len(all_entries), "Lifecycle inventory aggregate artifact count mismatch")
    validation.check(inventory_manifest.get("artifactSetHash") == hashlib.sha256(rfc8785.dumps(all_entries)).hexdigest(), "Lifecycle inventory aggregate artifact-set hash mismatch")
    expected_by_store = {
        store_kind: {entry.get("artifactId") for entry in all_entries if entry.get("storeKind") == store_kind}
        for store_kind in store_kinds
    }
    derived_counts = {store_kind: len(ids) for store_kind, ids in expected_by_store.items()}
    validation.check(inventory_manifest.get("storeCounts") == derived_counts, "Lifecycle inventory store counts differ from its pages")

    for row in stores:
        expected_ids = expected_by_store.get(row.get("storeKind"), set())
        expected_artifact_set_hash = hashlib.sha256(rfc8785.dumps(sorted(expected_ids))).hexdigest()
        validation.check(
            row.get("artifactSetHash") == expected_artifact_set_hash,
            f"Lifecycle store {row.get('storeKind')} artifact set hash mismatch",
        )
        validation.check(
            row.get("expected") == len(expected_ids),
            f"Lifecycle store {row.get('storeKind')} expected artifacts differ from the signed lifecycle inventory",
        )
        if row.get("state") == "not-applicable":
            validation.check(not expected_ids, f"Lifecycle store {row.get('storeKind')} is not-applicable despite enumerated artifacts")
        validation.check(
            row.get("expected", 0) == row.get("deleted", 0) + row.get("failed", 0) + row.get("notFound", 0) + row.get("remaining", 0) + row.get("retainedByPolicy", 0),
            f"Lifecycle store {row.get('storeKind')} counters do not exactly reconcile",
        )
        validation.check(
            (row.get("state") == "retained-by-policy") == (row.get("retainedByPolicy", 0) > 0),
            f"Lifecycle store {row.get('storeKind')} policy-retention state disagrees with its count",
        )
    try:
        requested = datetime.fromisoformat(receipt["requestedAt"].replace("Z", "+00:00"))
        blocked = datetime.fromisoformat(receipt["servingBlockedAt"].replace("Z", "+00:00"))
        deletion_started = datetime.fromisoformat(receipt["deletionStartedAt"].replace("Z", "+00:00"))
        validation.check(requested <= blocked <= deletion_started, "Lifecycle timestamps are out of order")
        for row in stores:
            enumerated = datetime.fromisoformat(row["enumeratedAt"].replace("Z", "+00:00"))
            validation.check(blocked <= enumerated <= deletion_started, f"Lifecycle store {row.get('storeKind')} was not enumerated before deletion started")
        validation.check(datetime.fromisoformat(inventory_manifest["enumeratedAt"].replace("Z", "+00:00")) <= deletion_started, "Lifecycle inventory manifest was not sealed before deletion started")
    except (KeyError, TypeError, ValueError) as exc:
        validation.check(False, f"Lifecycle receipt contains invalid pre-deletion timestamps: {exc}")
    if receipt.get("deletionState") == "completed":
        validation.check(receipt.get("servingState") == "blocked", "A completed deletion does not keep serving blocked")
        validation.check(all(row.get("failed", 0) == 0 for row in stores), "A completed deletion reports unresolved failures")
        validation.check(all(row.get("remaining", 0) == 0 for row in stores), "A completed deletion reports retained items")
        validation.check(bool(receipt.get("completedAt")), "A completed deletion has no terminal timestamp")
        try:
            completed = datetime.fromisoformat(receipt["completedAt"].replace("Z", "+00:00"))
            validation.check(deletion_started <= completed, "Lifecycle timestamps are out of order")
        except (KeyError, TypeError, ValueError) as exc:
            validation.check(False, f"Lifecycle receipt contains invalid timestamps: {exc}")
    try:
        registry = load_trusted_issuers(
            ROOT,
            issuer_registry_path=TRUST_REGISTRY_PATH,
            expected_registry_sha256=TRUST_REGISTRY_SHA256,
            require_external=REQUIRE_EXTERNAL_TRUST,
        )
        issuers = {row.get("issuerKeyId"): row for row in registry.get("issuers", []) if isinstance(row, dict)}
        issuer = issuers.get(receipt.get("issuerKeyId"))
        validation.check(issuer is not None and "lifecycle-deletion" in issuer.get("purposes", []), "Lifecycle receipt issuer is not authorized")
        receipt_preimage = {key: value for key, value in receipt.items() if key not in {"receiptHash", "signature"}}
        expected_receipt_hash = hashlib.sha256(rfc8785.dumps(receipt_preimage)).hexdigest()
        validation.check(receipt.get("receiptHash") == expected_receipt_hash, "Lifecycle receipt hash mismatch")
        if issuer is not None:
            sealed = datetime.fromisoformat(receipt["sealedAt"].replace("Z", "+00:00"))
            valid_from = datetime.fromisoformat(issuer["validFrom"].replace("Z", "+00:00"))
            valid_until = datetime.fromisoformat(issuer["validUntil"].replace("Z", "+00:00"))
            validation.check(valid_from <= sealed < valid_until, "Lifecycle receipt was signed outside issuer validity")
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(issuer.get("publicKeyBase64", ""), validate=True))
            public_key.verify(base64.b64decode(receipt.get("signature", ""), validate=True), bytes.fromhex(receipt.get("receiptHash", "")))
            validation.check(True, "Lifecycle receipt signature verified")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Lifecycle receipt signature verification failed: {exc}")


def validate_prompt_outputs(validation: Validation) -> None:
    """Every prompt output template must validate against its declared contract."""
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
    except ImportError as exc:
        validation.check(False, f"Standards validation dependency missing ({exc})")
        return

    schemas = []
    for path in sorted((ROOT / "contracts").glob("*.schema.json")):
        try:
            schemas.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Unable to load contract {path.name}: {exc}")
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas if "$id" in schema]
    )

    for path in sorted((ROOT / "prompts").glob("*.prompt.md")):
        text = path.read_text(encoding="utf-8")
        match = re.search(r"^outputContract:\s*(.+)$", text, re.MULTILINE)
        validation.check(match is not None, f"Missing outputContract in {path.name}")
        if match is None:
            continue
        file_part, _, fragment = match.group(1).strip().partition("#")
        target = (path.parent / file_part).resolve()
        if not target.is_file():
            continue
        schema_id = json.loads(target.read_text(encoding="utf-8")).get("$id")
        reference = f"{schema_id}#{fragment}" if fragment else schema_id

        blocks = re.findall(r"^# Output\b.*?```json\n(.*?)\n```", text, re.MULTILINE | re.DOTALL)
        validation.check(len(blocks) == 1, f"Expected exactly one output template in {path.name}, found {len(blocks)}")
        for block in blocks:
            try:
                instance = json.loads(block)
            except Exception as exc:  # noqa: BLE001
                validation.check(False, f"Output template in {path.name} is not valid JSON: {exc}")
                continue
            errors = list(
                Draft202012Validator({"$ref": reference}, registry=registry, format_checker=FormatChecker()).iter_errors(instance)
            )
            validation.check(
                not errors,
                f"Output template in {path.name} violates its contract: " + "; ".join(error.message for error in errors),
            )


def validate_evidence_integrity(validation: Validation) -> None:
    try:
        import rfc8785  # type: ignore[import-not-found]
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc}); run: python -m pip install -r requirements-validation.txt")
        return

    bundle = load_json("examples/evidence-bundle.json", validation)
    standalone = load_json("examples/evidence-record.json", validation)
    if not isinstance(bundle, dict) or not isinstance(standalone, dict):
        return

    records = [record for record in bundle.get("records", []) if isinstance(record, dict)]
    for record in records + [standalone]:
        payload = record.get("payload")
        expected = record.get("payloadHash")
        validation.check(record.get("hashAlgorithm") == "sha256-jcs", f"Evidence {record.get('evidenceId')} uses an unsupported hash algorithm")
        if payload is None:
            continue
        actual = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()
        validation.check(actual == expected, f"Evidence {record.get('evidenceId')} payloadHash mismatch: expected {actual}")

    by_id = {record.get("evidenceId"): record for record in records}
    validation.check(len(by_id) == len(records), "Evidence bundle contains duplicate IDs")
    dependency_graph = {
        record.get("evidenceId"): [
            dependency
            for dependency in record.get("provenance", {}).get("inputEvidenceIds", [])
            if dependency in by_id
        ]
        for record in records
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(evidence_id: str) -> None:
        if evidence_id in visiting:
            validation.check(False, f"Evidence dependency graph contains a cycle at {evidence_id}")
            return
        if evidence_id in visited:
            return
        visiting.add(evidence_id)
        for dependency_id in dependency_graph.get(evidence_id, []):
            visit(dependency_id)
        visiting.remove(evidence_id)
        visited.add(evidence_id)

    for evidence_id in dependency_graph:
        visit(evidence_id)
    for record in records:
        if record.get("maturity") == "usage-proven":
            proof = record.get("usageProof")
            validation.check(
                isinstance(proof, dict)
                and isinstance(proof.get("proofArtifactRef"), str)
                and proof.get("proofArtifactRef", "").startswith("artifact://")
                and re.fullmatch(r"[a-fA-F0-9]{64}", proof.get("proofArtifactSha256", "")) is not None
                and re.fullmatch(r"[a-fA-F0-9]{64}", proof.get("issuerRegistrySha256", "")) is not None,
                f"Evidence {record.get('evidenceId')} usage-proven maturity has an invalid independent usage-proof reference",
            )
            if isinstance(proof, dict) and proof.get("proofArtifactRef", "").startswith("artifact://"):
                validation.check(
                    False,
                    f"Evidence {record.get('evidenceId')} usage proof cannot be resolved and authenticated without a runtime artifact resolver and independent issuer registry",
                )
        dependencies = record.get("provenance", {}).get("inputEvidenceIds", [])
        unresolved = [dependency for dependency in dependencies if dependency not in by_id]
        validation.check(not unresolved, f"Evidence {record.get('evidenceId')} has unresolved dependencies {unresolved}")
        if unresolved:
            continue
        try:
            created = datetime.fromisoformat(record["createdAt"].replace("Z", "+00:00"))
            for dependency_id in dependencies:
                dependency_created = datetime.fromisoformat(by_id[dependency_id]["createdAt"].replace("Z", "+00:00"))
                validation.check(
                    dependency_created <= created,
                    f"Evidence {record.get('evidenceId')} predates dependency {dependency_id}",
                )
        except (KeyError, TypeError, ValueError) as exc:
            validation.check(False, f"Evidence {record.get('evidenceId')} has invalid causal timestamps: {exc}")
        bindings = sorted(
            ({"evidenceId": dependency, "recordHash": by_id[dependency].get("recordHash")} for dependency in dependencies),
            key=lambda item: item["evidenceId"],
        )
        expected_dependency_hash = hashlib.sha256(rfc8785.dumps(bindings)).hexdigest()
        validation.check(
            record.get("dependencyHash") == expected_dependency_hash,
            f"Evidence {record.get('evidenceId')} dependencyHash mismatch: expected {expected_dependency_hash}",
        )
        expected_record_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in record.items() if key != "recordHash"})).hexdigest()
        validation.check(
            record.get("recordHash") == expected_record_hash,
            f"Evidence {record.get('evidenceId')} recordHash mismatch: expected {expected_record_hash}",
        )

    twin = by_id.get(standalone.get("evidenceId"))
    validation.check(twin is not None, "Standalone evidence example is absent from the bundle")
    if twin is not None:
        validation.check(twin == standalone, "Standalone and bundled evidence records differ for the same evidence ID")

    for record in records:
        for key in ("sourceId", "sourceVersion", "policyHash", "authorizationScopeId"):
            for dependency_id in record.get("provenance", {}).get("inputEvidenceIds", []):
                dependency = by_id.get(dependency_id)
                if dependency is None:
                    continue
                validation.check(
                    dependency.get(key) == record.get(key),
                    f"Evidence {record.get('evidenceId')} depends on {dependency_id} with a different {key}",
                )
        logical_key = record.get("logicalKey")
        if not isinstance(logical_key, dict):
            continue
        evidence_id = record.get("evidenceId")
        for key in ("authorizationScopeId", "sourceId", "sourceVersion", "policyHash"):
            validation.check(
                logical_key.get(key) == record.get(key),
                f"Evidence {evidence_id} logicalKey {key} differs from the record",
            )
        validation.check(
            logical_key.get("subjectKind") == record.get("subject", {}).get("subjectKind"),
            f"Evidence {evidence_id} logicalKey subjectKind differs from its subject",
        )
        validation.check(
            logical_key.get("subjectId") == record.get("subject", {}).get("subjectId"),
            f"Evidence {evidence_id} logicalKey subjectId differs from its subject",
        )
        validation.check(
            logical_key.get("predicate") == record.get("claim", {}).get("predicate"),
            f"Evidence {evidence_id} logicalKey predicate differs from its claim",
        )
        validation.check(
            logical_key.get("methodVersion") == record.get("provenance", {}).get("methodVersion"),
            f"Evidence {evidence_id} logicalKey methodVersion differs from its provenance",
        )
        sample = record.get("sample")
        if sample is not None and logical_key.get("samplePlanHash") is not None:
            expected_sample_hash = hashlib.sha256(rfc8785.dumps(sample)).hexdigest()
            validation.check(logical_key.get("samplePlanHash") == expected_sample_hash, f"Evidence {evidence_id} logicalKey sample plan hash differs from its sample")
        kind = record.get("kind")
        payload = record.get("payload") or {}
        if kind in {"field-profile", "quality-score"}:
            validation.check(logical_key.get("assetId") == record.get("subject", {}).get("assetId"), f"Evidence {evidence_id} logicalKey asset differs from its subject")
            validation.check(logical_key.get("statisticFamily") == kind, f"Evidence {evidence_id} logicalKey statistic family differs from its kind")
            validation.check(logical_key.get("fieldPath") == record.get("subject", {}).get("fieldPath"), f"Evidence {evidence_id} logicalKey field path differs from its subject")
        if kind == "identity":
            expected_identity = {"scopePaths": sorted(payload.get("scopePaths", [])), "localKeyPaths": payload.get("localKeyPaths", []), "versionPaths": []}
            validation.check(logical_key.get("identityCoordinate") == expected_identity, f"Evidence {evidence_id} logicalKey identity coordinate differs from its payload")
        if kind == "grain":
            paths = payload.get("paths", [])
            expected_identity = {"scopePaths": sorted(paths[:1]), "localKeyPaths": paths[1:2], "versionPaths": paths[2:]}
            validation.check(logical_key.get("identityCoordinate") == expected_identity, f"Evidence {evidence_id} logicalKey grain coordinate differs from its payload")
        if kind == "relationship-validation":
            expected_relationship = {"kind": payload.get("relationshipKind"), "left": payload.get("left"), "right": payload.get("right"), "validatorVersion": payload.get("validator", {}).get("methodVersion")}
            validation.check(logical_key.get("relationshipCoordinate") == expected_relationship, f"Evidence {evidence_id} logicalKey relationship coordinate differs from its payload")
        if kind == "business-scenario":
            expected_set_hash = hashlib.sha256(rfc8785.dumps(sorted(record.get("provenance", {}).get("inputEvidenceIds", [])))).hexdigest()
            validation.check(logical_key.get("businessConceptCoordinate", {}).get("supportingEvidenceSetHash") == expected_set_hash, f"Evidence {evidence_id} logicalKey supporting evidence set differs from provenance")
            validation.check(logical_key.get("businessConceptCoordinate", {}).get("conceptKind") == "scenario", f"Evidence {evidence_id} logicalKey business concept kind differs from its evidence kind")
            validation.check(bool(logical_key.get("businessConceptCoordinate", {}).get("normalizedName")), f"Evidence {evidence_id} logicalKey business concept name is empty")
        if kind in {"asset-purpose", "semantic-label"}:
            semantic = logical_key.get("semanticCoordinate", {})
            validation.check(semantic.get("assetId") == record.get("subject", {}).get("assetId"), f"Evidence {evidence_id} logicalKey semantic asset differs from its subject")
            validation.check(semantic.get("fieldPath") == record.get("subject", {}).get("fieldPath"), f"Evidence {evidence_id} logicalKey semantic field differs from its subject")
            validation.check(semantic.get("semanticKind") == kind, f"Evidence {evidence_id} logicalKey semantic kind differs from its evidence kind")


def validate_capability_negotiation(validation: Validation) -> None:
    descriptor = load_json("examples/source-descriptor.json", validation)
    matrix = load_json("pipeline/capability-matrix.json", validation)
    if not isinstance(descriptor, dict) or not isinstance(matrix, dict):
        return

    requested = set(descriptor.get("requestedCapabilities", []))
    declared = set(descriptor.get("connectorDeclaredCapabilities", []))
    authorized = set(descriptor.get("policyAuthorizedCapabilities", []))
    effective = set(descriptor.get("effectiveCapabilities", []))
    validation.check(
        effective == requested & declared & authorized,
        "Effective capabilities are not the requested/declared/authorized intersection",
    )
    try:
        import rfc8785  # type: ignore[import-not-found]
        connector_preimage = {
            "connectorId": descriptor.get("connectorId"),
            "connectorVersion": descriptor.get("connectorVersion"),
            "capabilities": sorted(declared),
        }
        expected_connector_hash = hashlib.sha256(rfc8785.dumps(connector_preimage)).hexdigest()
        validation.check(descriptor.get("connectorCapabilityHash") == expected_connector_hash, "Source connector capability hash is not derivable")
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")

    operations = set(descriptor.get("authorizationScope", {}).get("authorizedOperations", []))
    required_by_capability = {
        row.get("id"): set(row.get("requiresAuthorization", []))
        for row in matrix.get("capabilities", [])
        if isinstance(row, dict)
    }
    for capability in effective:
        missing = required_by_capability.get(capability, set()) - operations
        validation.check(not missing, f"Capability {capability} lacks authorized operations {sorted(missing)}")


def validate_source_kind_registry(validation: Validation, scenarios_by_feature: dict[str, set[str]]) -> None:
    profiles = load_json("pipeline/source-kind-profiles.json", validation)
    stages = load_json("pipeline/stages.json", validation)
    source_schema = load_json("contracts/source-descriptor.schema.json", validation)
    registration_schema = load_json("contracts/source-registration-request.schema.json", validation)
    extension_schema = load_json("contracts/source-profile-extension.schema.json", validation)
    run_schema = load_json("contracts/profiling-run.schema.json", validation)
    matrix = load_json("pipeline/capability-matrix.json", validation)
    try:
        import yaml  # type: ignore[import-not-found]
        source_taxonomy = yaml.safe_load((ROOT / "taxonomies" / "source-kinds.yaml").read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read the source-kind taxonomy: {exc}")
        return
    if not all(isinstance(value, dict) for value in (profiles, stages, source_schema, registration_schema, extension_schema, run_schema, matrix, source_taxonomy)):
        return

    canonical_ids = [row.get("id") for row in stages.get("stages", []) if isinstance(row, dict)]
    stage_ids = set(canonical_ids)
    stage_by_id = {row.get("id"): row for row in stages.get("stages", []) if isinstance(row, dict)}
    capability_ids = {row.get("id") for row in matrix.get("capabilities", []) if isinstance(row, dict)}
    boundary_modes = set(
        run_schema.get("properties", {}).get("sourceBoundary", {}).get("properties", {}).get("mode", {}).get("enum", [])
    )
    profile_rows = [row for row in profiles.get("sourceKinds", []) if isinstance(row, dict)]
    profile_kind_list = [row.get("id") for row in profile_rows]
    declared_kinds = set(profile_kind_list)
    validation.check(len(profile_kind_list) == len(declared_kinds), "Source-kind profiles contain duplicate kind IDs")
    schema_kinds = set(source_schema.get("properties", {}).get("kind", {}).get("enum", []))
    validation.check(declared_kinds == schema_kinds, "Source-kind registry differs from the source-descriptor enum")
    registration_kinds = set(registration_schema.get("properties", {}).get("kind", {}).get("enum", []))
    extension_kinds = set(extension_schema.get("properties", {}).get("sourceKind", {}).get("enum", []))
    taxonomy_rows = [row for row in source_taxonomy.get("sourceKinds", []) if isinstance(row, dict)]
    taxonomy_kind_list = [row.get("id") for row in taxonomy_rows]
    taxonomy_kinds = set(taxonomy_kind_list)
    validation.check(len(taxonomy_kind_list) == len(taxonomy_kinds), "Source-kind taxonomy contains duplicate kind IDs")
    validation.check(declared_kinds == registration_kinds, "Source-kind registry differs from the registration contract")
    validation.check(declared_kinds == extension_kinds, "Source-kind registry differs from the extension contract")
    validation.check(declared_kinds == taxonomy_kinds, "Source-kind registry differs from the source-kind taxonomy")

    taxonomy_capabilities = set(source_taxonomy.get("capabilities", []))
    validation.check(taxonomy_capabilities == capability_ids, "Source-kind taxonomy capabilities differ from the capability matrix")
    taxonomy_by_kind = {row.get("id"): row for row in taxonomy_rows}

    common_list = profiles.get("commonStages", [])
    common = set(common_list)
    validation.check(len(common_list) == len(common), "Common stages contain duplicates")
    validation.check(common <= stage_ids, "Common stages contain unknown stage IDs")
    validation.check(common_list == [stage_id for stage_id in canonical_ids if stage_id in common], "Common stages are not in canonical pipeline order")

    for row in profile_rows:
        kind = row.get("id")
        for bucket_name in ("supportedStages", "conditionalStages", "unavailableStages"):
            values = row.get(bucket_name, [])
            validation.check(len(values) == len(set(values)), f"Source kind {kind} {bucket_name} contains duplicates")
        declared_stages = set(row.get("supportedStages", [])) | set(row.get("conditionalStages", [])) | set(row.get("unavailableStages", []))
        validation.check(declared_stages <= stage_ids, f"Source kind {kind} declares unknown stages")
        validation.check(
            common | declared_stages == stage_ids,
            f"Source kind {kind} does not account for every canonical stage",
        )
        validation.check(
            set(row.get("requiredConnectorCapabilities", [])) <= capability_ids,
            f"Source kind {kind} requires unknown connector capabilities",
        )
        declared_capabilities = set(row.get("requiredConnectorCapabilities", []))
        for stage_id in common | set(row.get("supportedStages", [])):
            stage = stage_by_id.get(stage_id, {})
            missing = set(stage.get("requiredCapabilities", [])) - declared_capabilities
            validation.check(
                not missing,
                f"Source kind {kind} declares stage {stage_id} supported but lacks capabilities {sorted(missing)}",
            )
            any_of = set(stage.get("requiredCapabilitiesAny", []))
            validation.check(
                not any_of or bool(any_of & declared_capabilities),
                f"Source kind {kind} declares stage {stage_id} supported but satisfies none of {sorted(any_of)}",
            )
        for stage_id in row.get("conditionalStages", []):
            stage = stage_by_id.get(stage_id, {})
            required = set(stage.get("requiredCapabilities", []))
            any_of = set(stage.get("requiredCapabilitiesAny", []))
            unmet = bool(required - declared_capabilities) or bool(any_of and not (any_of & declared_capabilities))
            validation.check(
                unmet,
                f"Source kind {kind} classifies stage {stage_id} conditional although its declared capabilities already satisfy it",
            )
            validation.check(
                not stage.get("required"),
                f"Source kind {kind} cannot execute required stage {stage_id}; it is classified conditional",
            )
        buckets = (set(row.get("supportedStages", [])), set(row.get("conditionalStages", [])), set(row.get("unavailableStages", [])))
        validation.check(
            sum(len(bucket) for bucket in buckets) == len(buckets[0] | buckets[1] | buckets[2]),
            f"Source kind {kind} classifies a stage in more than one bucket",
        )
        validation.check(
            not (common & (buckets[0] | buckets[1] | buckets[2])),
            f"Source kind {kind} reclassifies a common stage",
        )
        validation.check(
            set(row.get("consistencyBoundaryModes", [])) <= boundary_modes,
            f"Source kind {kind} declares unknown consistency boundary modes",
        )
        validation.check(bool(row.get("validators")), f"Source kind {kind} declares no validators")
        taxonomy_validators = set(taxonomy_by_kind.get(kind, {}).get("relationshipValidators", []))
        validation.check(set(row.get("validators", [])) == taxonomy_validators, f"Source kind {kind} validators differ from the taxonomy")
        for field in ("positiveScenario", "failureScenario"):
            reference = row.get(field, "")
            feature, _, scenario = reference.partition(":")
            validation.check(
                scenario in scenarios_by_feature.get(feature, set()),
                f"Source kind {kind} {field} does not resolve: {reference}",
            )


def validate_run_lifecycle_examples(validation: Validation) -> None:
    try:
        import rfc8785  # type: ignore[import-not-found]
        import yaml  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        validation.check(False, f"Lifecycle validation dependency missing ({exc})")
        return

    examples = {
        state: load_json(f"examples/profiling-run-{state}.json", validation)
        for state in ("pending", "running", "resume")
    }
    examples["completed"] = load_json("examples/profiling-run.json", validation)
    stages = load_json("pipeline/stages.json", validation)
    if not all(isinstance(value, dict) for value in (*examples.values(), stages)):
        return
    policy = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))
    policy_budget = policy.get("execution", {}).get("budgets", {})
    expected_limits = {
        "sourceBytesRead": policy_budget.get("sourceBytesRead"),
        "modelInputTokens": policy_budget.get("modelInputTokens"),
        "modelOutputTokens": policy_budget.get("modelOutputTokens"),
        "wallClockMilliseconds": (policy_budget.get("wallClockSeconds") or 0) * 1000,
        "relationshipValidations": policy_budget.get("relationshipValidations"),
    }
    canonical_ids = [row.get("id") for row in stages.get("stages", []) if isinstance(row, dict)]

    def when(value: Any) -> datetime | None:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else None

    for name, run in examples.items():
        validation.check(
            [row.get("stageId") for row in run.get("stages", [])] == canonical_ids,
            f"{name} run does not carry the canonical stage inventory",
        )
        accepted, observed = when(run.get("acceptedAt")), when(run.get("observedAt"))
        validation.check(
            accepted is not None and observed is not None and accepted <= observed,
            f"{name} run acceptance/observation timestamps are invalid",
        )
        budget = run.get("budget", {})
        validation.check(budget.get("limits") == expected_limits, f"{name} run budget limits differ from policy")
        limits, usage = budget.get("limits", {}), budget.get("usage", {})
        for dimension, limit in limits.items():
            validation.check(
                0 <= usage.get(dimension, -1) <= limit,
                f"{name} run budget {dimension} exceeds its policy limit",
            )
        exhausted = set(budget.get("exhaustedDimensions", []))
        validation.check(exhausted <= set(limits), f"{name} run names an unknown exhausted budget dimension")
        derived_exhausted = {
            dimension for dimension, limit in limits.items()
            if usage.get(dimension, -1) >= limit
        }
        validation.check(exhausted == derived_exhausted, f"{name} run budget exhaustion markers differ from measured usage")
        for dimension in exhausted:
            validation.check(
                usage.get(dimension, -1) >= limits.get(dimension, 0),
                f"{name} run marks {dimension} exhausted below its limit",
            )
        validation.check(
            bool(budget.get("stoppedAt")) == bool(exhausted),
            f"{name} run budget stoppedAt disagrees with exhaustion state",
        )
        stopped = when(budget.get("stoppedAt"))
        if stopped is not None:
            validation.check(accepted <= stopped <= observed, f"{name} run budget stop time is outside the observed run interval")
            validation.check(run.get("state") == "completed-partial", f"{name} run remains {run.get('state')} after budget exhaustion")

    pending = examples["pending"]
    validation.check(
        pending.get("state") == "pending" and pending.get("lease") is None and pending.get("fencingToken") is None,
        "Pending run must exist before lease and fencing-token acquisition",
    )
    validation.check(pending.get("startedAt") is None, "Pending run falsely records execution start")

    running = examples["running"]
    lease = running.get("lease", {})
    validation.check(running.get("state") == "running" and isinstance(lease, dict), "Running run has no active lease")
    validation.check(
        lease.get("fencingToken") == running.get("fencingToken"),
        "Running run lease fencing token differs from the run",
    )
    observed = when(running.get("observedAt"))
    expires = when(lease.get("expiresAt"))
    validation.check(
        observed is not None and expires is not None and observed < expires,
        "Running run lease is not valid at state observation time",
    )
    started = when(running.get("startedAt"))
    validation.check(
        started is not None and observed is not None and started <= observed,
        "Running run starts after its observation time",
    )

    completed = examples["completed"]
    validation.check(
        completed.get("lease") is None and isinstance(completed.get("fencingToken"), int),
        "Terminal run did not release its lease while preserving fencing token",
    )
    validation.check(
        when(completed.get("completedAt")) <= when(completed.get("observedAt")),
        "Terminal run is observed before completion",
    )

    resume = examples["resume"]
    checkpoint = resume.get("resumeCheckpoint", {})
    predecessor = checkpoint.get("predecessor", {})
    validation.check(resume.get("mode") == "resume", "Resume example is not a resume run")
    validation.check(
        checkpoint.get("predecessorRunId") == resume.get("predecessorRunId") == predecessor.get("runId"),
        "Resume checkpoint predecessor run binding differs",
    )
    validation.check(
        checkpoint.get("predecessorState") == predecessor.get("state"),
        "Resume checkpoint predecessor state differs",
    )
    predecessor_completed = when(predecessor.get("completedAt"))
    checkpoint_created = when(checkpoint.get("createdAt"))
    checkpoint_sealed = when(checkpoint.get("sealedAt"))
    resume_accepted = when(resume.get("acceptedAt"))
    resume_started = when(resume.get("startedAt"))
    validation.check(
        None not in {predecessor_completed, checkpoint_created, checkpoint_sealed, resume_accepted, resume_started}
        and predecessor_completed <= checkpoint_created <= checkpoint_sealed <= resume_accepted <= resume_started,
        "Resume checkpoint chronology is causally impossible",
    )
    expected_predecessor_hash = hashlib.sha256(rfc8785.dumps(predecessor)).hexdigest()
    validation.check(
        checkpoint.get("predecessorRunHash") == expected_predecessor_hash,
        "Resume checkpoint predecessor run hash mismatch",
    )
    completed_receipts = sorted(checkpoint.get("completedDependencyReceiptIds", []))
    expected_set_hash = hashlib.sha256(rfc8785.dumps(completed_receipts)).hexdigest()
    validation.check(
        checkpoint.get("completedDependencySetHash") == expected_set_hash,
        "Resume checkpoint completed dependency set hash mismatch",
    )
    validation.check(
        completed_receipts == sorted(predecessor.get("completedReceiptIds", [])),
        "Resume checkpoint completed dependency receipts differ from its predecessor",
    )
    completed_stages = checkpoint.get("completedDependencyStageIds", [])
    validation.check(
        completed_stages == predecessor.get("completedStageIds", []),
        "Resume checkpoint completed dependency stages differ from its predecessor",
    )
    resume_stage = checkpoint.get("resumeFromStage")
    resume_index = canonical_ids.index(resume_stage) if resume_stage in canonical_ids else -1
    validation.check(
        completed_stages == canonical_ids[:resume_index],
        "Resume checkpoint does not prove every stage before the resume point terminal",
    )
    validation.check(
        checkpoint.get("resumeFromStage") == resume.get("resumeFromStage"),
        "Resume checkpoint stage differs from the run",
    )
    work = checkpoint.get("workProgress", {})
    progress_uri = work.get("manifestUri", "")
    progress_path = (ROOT / progress_uri.removeprefix("package://")).resolve() if progress_uri.startswith("package://") else None
    validation.check(progress_path is not None and progress_path.is_file() and ROOT.resolve() in progress_path.parents, "Resume work progress manifest does not resolve inside the package")
    if progress_path is not None and progress_path.is_file() and ROOT.resolve() in progress_path.parents:
        progress = json.loads(progress_path.read_text(encoding="utf-8"))
        progress_hash = hashlib.sha256(progress_path.read_bytes()).hexdigest()
        validation.check(work.get("manifestContentHash") == progress_hash, "Resume work progress manifest byte hash mismatch")
        manifest_bindings = {
            "runId": predecessor.get("runId"),
            "sourceId": resume.get("sourceId"),
            "authorizationScopeId": resume.get("authorizationScopeId"),
            "stageId": checkpoint.get("resumeFromStage"),
            "sourceVersionCandidate": resume.get("sourceVersionCandidate"),
        }
        for key, expected_value in manifest_bindings.items():
            validation.check(progress.get(key) == expected_value, f"Resume work progress manifest binding {key} differs")
        for key in ("manifestId", "stageId", "checkpointUnit", "completedItemCount", "failedItemCount", "pendingItemCount", "completedItemSetHash"):
            validation.check(work.get(key) == progress.get(key), f"Resume work progress {key} differs from its manifest")
        item_ids: dict[str, list[str]] = {"completed": [], "failed": [], "pending": []}
        page_totals = {"completedItemCount": 0, "failedItemCount": 0, "pendingItemCount": 0}
        pages = progress.get("pages", [])
        validation.check([row.get("ordinal") for row in pages] == list(range(len(pages))), "Resume work progress page ordinals are not contiguous")
        for page in pages:
            page_uri = page.get("pageUri", "")
            page_path = (ROOT / page_uri.removeprefix("package://")).resolve() if page_uri.startswith("package://") else None
            validation.check(page_path is not None and page_path.is_file() and ROOT.resolve() in page_path.parents, "Resume work progress page does not resolve inside the package")
            if page_path is None or not page_path.is_file() or ROOT.resolve() not in page_path.parents:
                continue
            page_document = json.loads(page_path.read_text(encoding="utf-8"))
            validation.check(page.get("pageContentHash") == hashlib.sha256(page_path.read_bytes()).hexdigest(), "Resume work progress page byte hash mismatch")
            validation.check(page_document.get("manifestId") == progress.get("manifestId") and page_document.get("ordinal") == page.get("ordinal"), "Resume work progress page binding differs")
            for state in item_ids:
                item_ids[state].extend(page_document.get(f"{state}ItemIds", []))
            for count_key, ids_key in (("completedItemCount", "completedItemIds"), ("failedItemCount", "failedItemIds"), ("pendingItemCount", "pendingItemIds")):
                actual = len(page_document.get(ids_key, []))
                validation.check(page.get(count_key) == actual, f"Resume work progress page {count_key} mismatch")
                page_totals[count_key] += actual
            validation.check(page.get("completedItemSetHash") == hashlib.sha256(rfc8785.dumps(sorted(page_document.get("completedItemIds", [])))).hexdigest(), "Resume work progress page completed-item hash mismatch")
        for count_key, total in page_totals.items():
            validation.check(progress.get(count_key) == total, f"Resume work progress aggregate {count_key} mismatch")
        validation.check(progress.get("completedItemSetHash") == hashlib.sha256(rfc8785.dumps(sorted(item_ids["completed"]))).hexdigest(), "Resume work progress completed-item set hash mismatch")
        all_item_ids = item_ids["completed"] + item_ids["failed"] + item_ids["pending"]
        validation.check(len(all_item_ids) == len(set(all_item_ids)), "Resume work progress item IDs are not globally pairwise disjoint across pages and states")
    cumulative = checkpoint.get("cumulativeBudgetUsage", {})
    predecessor_usage = predecessor.get("budgetUsage", {})
    validation.check(cumulative == predecessor_usage, "Resume checkpoint cumulative budget differs from predecessor usage")
    for dimension, predecessor_value in cumulative.items():
        validation.check(resume.get("budget", {}).get("usage", {}).get(dimension, -1) >= predecessor_value, f"Resume cumulative budget reset {dimension}")
    for key in (
        "sourceId", "sourceVersionCandidate", "sourceVersion", "connectorId", "connectorVersion",
        "connectorCapabilityHash", "authorizationScopeId", "policyHash", "pipelineVersion",
        "methodSetHash", "taxonomyVersion", "revocationEpoch",
    ):
        validation.check(
            checkpoint.get(key) == resume.get(key) == predecessor.get(key),
            f"Resume checkpoint {key} is incompatible with its run or predecessor",
        )
    validation.check(
        checkpoint.get("boundaryId") == resume.get("sourceBoundary", {}).get("boundaryId") == predecessor.get("boundaryId"),
        "Resume checkpoint boundary differs",
    )
    validation.check(
        checkpoint.get("boundaryExpiresAt") == resume.get("sourceBoundary", {}).get("expiresAt") == predecessor.get("boundaryExpiresAt"),
        "Resume checkpoint boundary expiry differs",
    )
    observed = when(resume.get("observedAt"))
    boundary_expires = when(checkpoint.get("boundaryExpiresAt"))
    validation.check(
        observed is not None and boundary_expires is not None and observed < boundary_expires,
        "Resume checkpoint source boundary is expired",
    )
    checkpoint_preimage = {
        key: value for key, value in checkpoint.items() if key not in {"checkpointHash", "signature"}
    }
    expected_checkpoint_hash = hashlib.sha256(rfc8785.dumps(checkpoint_preimage)).hexdigest()
    validation.check(checkpoint.get("checkpointHash") == expected_checkpoint_hash, "Resume checkpoint hash mismatch")
    try:
        registry = load_trusted_issuers(
            ROOT,
            issuer_registry_path=TRUST_REGISTRY_PATH,
            expected_registry_sha256=TRUST_REGISTRY_SHA256,
            require_external=REQUIRE_EXTERNAL_TRUST,
        )
        issuer = next((row for row in registry.get("issuers", []) if row.get("issuerKeyId") == checkpoint.get("issuerKeyId")), None)
        validation.check(issuer is not None and "resume-checkpoint" in issuer.get("purposes", []), "Resume checkpoint issuer is not authorized")
        if issuer is not None:
            sealed = when(checkpoint.get("sealedAt"))
            valid_from = when(issuer.get("validFrom"))
            valid_until = when(issuer.get("validUntil"))
            validation.check(valid_from <= sealed < valid_until, "Resume checkpoint was signed outside issuer validity")
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(issuer.get("publicKeyBase64", ""), validate=True))
            public_key.verify(base64.b64decode(checkpoint.get("signature", ""), validate=True), bytes.fromhex(checkpoint.get("checkpointHash", "")))
            validation.check(True, "Resume checkpoint signature verified")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Resume checkpoint signature verification failed: {exc}")


def validate_run_accounting(validation: Validation) -> None:
    validate_run_lifecycle_examples(validation)
    run = load_json("examples/profiling-run.json", validation)
    stages = load_json("pipeline/stages.json", validation)
    receipt_bundle = load_json("examples/stage-receipt-bundle.json", validation)
    stage_details = load_json("examples/stage-output-details.json", validation)
    profile = load_json("examples/profile-manifest.json", validation)
    evidence_bundle = load_json("examples/evidence-bundle.json", validation)
    source_descriptor = load_json("examples/source-descriptor.json", validation)
    boundary_opening = load_json("examples/source-boundary-opening.json", validation)
    boundary_verification = load_json("examples/source-boundary-verification.json", validation)
    source_structure = load_json("examples/source-structure.json", validation)
    if not all(isinstance(value, dict) for value in (run, stages, receipt_bundle, stage_details, profile, evidence_bundle, source_descriptor, boundary_opening, boundary_verification, source_structure)):
        return

    stage_rows = [row for row in stages.get("stages", []) if isinstance(row, dict)]
    canonical_ids = [row.get("id") for row in stage_rows]
    required_by_id = {row.get("id"): bool(row.get("required")) for row in stage_rows}
    dependencies_by_id = {row.get("id"): row.get("dependencies", []) for row in stage_rows}
    receipt_type_by_id = {row.get("id"): row.get("receipt") for row in stage_rows}
    receipt_schema = load_json("contracts/stage-receipt-bundle.schema.json", validation)
    if isinstance(receipt_schema, dict):
        schema_stage_ids = set(receipt_schema.get("$defs", {}).get("stageId", {}).get("enum", []))
        schema_receipt_types = set(receipt_schema.get("$defs", {}).get("receiptType", {}).get("enum", []))
        validation.check(schema_stage_ids == set(canonical_ids), "Stage receipt schema stage IDs differ from the pipeline registry")
        validation.check(schema_receipt_types == set(receipt_type_by_id.values()), "Stage receipt types differ from the pipeline registry")
    run_stages = [row for row in run.get("stages", []) if isinstance(row, dict)]
    run_ids = [row.get("stageId") for row in run_stages]
    validation.check(run_ids == canonical_ids, "Run example stages are not the canonical ordered stage set")
    validation.check(len(run_ids) == len(set(run_ids)), "Run example contains duplicate stage IDs")
    validation.check(receipt_bundle.get("runId") == run.get("runId"), "Stage receipt bundle names a different run")
    receipts = [row for row in receipt_bundle.get("receipts", []) if isinstance(row, dict)]
    receipt_ids = [row.get("receiptId") for row in receipts]
    receipt_stage_ids = [row.get("stageId") for row in receipts]
    validation.check(len(receipt_ids) == len(set(receipt_ids)), "Stage receipt bundle repeats a receipt ID")
    validation.check(len(receipts) == len(run_stages), "Completed run does not have exactly one receipt per canonical stage")
    validation.check(receipt_stage_ids == canonical_ids, "Stage receipt bundle is not in canonical stage order")
    receipts_by_id = {row.get("receiptId"): row for row in receipts}
    receipt_id_by_stage = {row.get("stageId"): row.get("receiptId") for row in receipts}
    referenced_receipts: set[str] = set()
    detail_rows = [row for row in stage_details.get("outputs", []) if isinstance(row, dict)]
    detail_stage_ids = [row.get("stageId") for row in detail_rows]
    validation.check(len(detail_stage_ids) == len(set(detail_stage_ids)), "Stage-output details repeat a stage ID")
    details_by_stage = {row.get("stageId"): row for row in detail_rows}
    asset_ids = {row.get("assetId") for row in profile.get("assets", []) if isinstance(row, dict)}
    evidence_ids = {row.get("evidenceId") for row in evidence_bundle.get("records", []) if isinstance(row, dict)}

    if run.get("mode") == "resume":
        validation.check(run.get("predecessorRunId") != run.get("runId"), "A run cannot resume from itself")
        validation.check(run.get("resumeFromStage") in canonical_ids, "A resume run names an unknown stage")

    terminal_states = {"completed", "completed-partial", "failed", "skipped", "cancelled"}
    total_completed = 0
    stages_by_id = {row.get("stageId"): row for row in run_stages}
    parse_time = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    run_started = parse_time(run.get("startedAt"))
    run_completed = parse_time(run.get("completedAt"))
    for row in run_stages:
        stage_id = row.get("stageId")
        validation.check(row.get("required") == required_by_id.get(stage_id), f"Run stage {stage_id} requiredness differs from the registry")
        expected = row.get("itemsExpected", 0)
        parts = sum(row.get(key, 0) for key in ("itemsCompleted", "itemsFailed", "itemsSkipped", "itemsUnavailable", "itemsNotRun", "itemsDeferred"))
        validation.check(expected == parts, f"Run stage {stage_id} counters do not reconcile to itemsExpected")
        validation.check(
            row.get("itemsAttempted", 0) == row.get("itemsCompleted", 0) + row.get("itemsFailed", 0),
            f"Run stage {stage_id} attempted work does not reconcile to completed plus failed work",
        )
        if row.get("state") == "completed":
            validation.check(expected == row.get("itemsCompleted", 0), f"Completed stage {stage_id} retains unfinished work")
        if row.get("applicability") == "not-applicable":
            validation.check(expected == row.get("itemsSkipped", 0), f"Not-applicable stage {stage_id} is not fully accounted as skipped")
        if row.get("applicability") == "unavailable":
            validation.check(expected == row.get("itemsUnavailable", 0), f"Unavailable stage {stage_id} is not fully accounted as unavailable")
        total_completed += row.get("itemsCompleted", 0)
        if run.get("state") in {"completed", "completed-partial", "failed", "cancelled"}:
            validation.check(row.get("state") in terminal_states, f"Run stage {stage_id} is not terminal in a terminal run")
            validation.check(bool(row.get("completedAt")), f"Run stage {stage_id} has no completion timestamp in a terminal run")
            validation.check(bool(row.get("receiptRefs")), f"Run stage {stage_id} has no terminal receipt")
            validation.check(len(row.get("receiptRefs", [])) == 1, f"Run stage {stage_id} does not have exactly one terminal receipt")
        for reference in row.get("receiptRefs", []):
            receipt_id = reference.get("receiptId") if isinstance(reference, dict) else None
            receipt = receipts_by_id.get(receipt_id)
            validation.check(receipt is not None, f"Run stage {stage_id} references missing receipt {receipt_id}")
            if receipt is None:
                continue
            referenced_receipts.add(receipt_id)
            validation.check(reference.get("receiptType") == receipt_type_by_id.get(stage_id), f"Run stage {stage_id} declares the wrong receipt type")
            validation.check(receipt.get("receiptType") == reference.get("receiptType"), f"Receipt {receipt_id} type differs from its reference")
            validation.check(receipt.get("stageId") == stage_id, f"Receipt {receipt_id} belongs to another stage")
            validation.check(receipt.get("runId") == run.get("runId"), f"Receipt {receipt_id} belongs to another run")
            for key in ("sourceId", "connectorId", "connectorVersion", "connectorCapabilityHash", "authorizationScopeId", "policyHash", "taxonomyVersion", "pipelineVersion", "methodSetHash", "revocationEpoch", "fencingToken"):
                validation.check(receipt.get(key) == run.get(key), f"Receipt {receipt_id} {key} differs from its run")
            validation.check(receipt.get("sourceVersionCandidate") == run.get("sourceVersionCandidate"), f"Receipt {receipt_id} source version candidate differs from its run")
            if stage_id in {"register-negotiate", "authorize-pre-read", "open-source-boundary"}:
                validation.check(receipt.get("sourceVersionStatus") == "candidate", f"Pre-discovery receipt {receipt_id} falsely claims a final source version")
                validation.check(receipt.get("sourceVersion") is None, f"Pre-discovery receipt {receipt_id} carries a not-yet-derived source version")
            else:
                validation.check(receipt.get("sourceVersionStatus") == "final", f"Post-discovery receipt {receipt_id} does not carry a final source version")
                validation.check(receipt.get("sourceVersion") == run.get("sourceVersion"), f"Receipt {receipt_id} sourceVersion differs from its run")
            expected_dependencies = [receipt_id_by_stage.get(dependency) for dependency in dependencies_by_id.get(stage_id, [])]
            validation.check(receipt.get("dependencyReceiptIds") == expected_dependencies, f"Receipt {receipt_id} dependency receipts differ from the stage graph")
            validation.check(receipt.get("attempt") == row.get("attempt"), f"Receipt {receipt_id} belongs to another attempt")
            validation.check(receipt.get("outcome") == row.get("state"), f"Receipt {receipt_id} outcome differs from its stage")
            validation.check(receipt.get("methodVersion") == row.get("methodVersion"), f"Receipt {receipt_id} method differs from its stage")
            validation.check(receipt.get("producedAt") == row.get("completedAt"), f"Receipt {receipt_id} timestamp differs from stage completion")
            expected_work = {
                "expected": row.get("itemsExpected"),
                "attempted": row.get("itemsAttempted"),
                "completed": row.get("itemsCompleted"),
                "failed": row.get("itemsFailed"),
                "skipped": row.get("itemsSkipped"),
                "unavailable": row.get("itemsUnavailable"),
                "notRun": row.get("itemsNotRun"),
                "deferred": row.get("itemsDeferred"),
            }
            validation.check(receipt.get("work") == expected_work, f"Receipt {receipt_id} work accounting differs from its stage")
            if stage_id in details_by_stage:
                items = details_by_stage[stage_id].get("items", [])
                item_ids = [item.get("itemId") for item in items if isinstance(item, dict)]
                validation.check(len(item_ids) == len(set(item_ids)), f"Stage-output details for {stage_id} repeat item IDs")
                outcome_counts = {
                    outcome: sum(1 for item in items if item.get("outcome") == outcome)
                    for outcome in ("completed", "unavailable", "not-applicable")
                }
                validation.check(outcome_counts["completed"] == expected_work["completed"], f"Stage-output details for {stage_id} completed count differs from receipt work")
                validation.check(outcome_counts["unavailable"] == expected_work["unavailable"], f"Stage-output details for {stage_id} unavailable count differs from receipt work")
                validation.check(outcome_counts["not-applicable"] == expected_work["skipped"], f"Stage-output details for {stage_id} not-applicable count differs from receipt work")
                for item in items:
                    validation.check(item.get("assetId") in asset_ids, f"Stage-output detail {item.get('itemId')} references a missing asset")
                    validation.check(set(item.get("evidenceRefs", [])) <= evidence_ids, f"Stage-output detail {item.get('itemId')} references missing evidence")
            outputs = receipt.get("outputs", [])
            output_keys = [(output.get("artifactId"), output.get("artifactUri")) for output in outputs]
            output_ids = [output.get("artifactId") for output in outputs]
            output_uris = [output.get("artifactUri") for output in outputs]
            validation.check(len(output_keys) == len(set(output_keys)), f"Receipt {receipt_id} contains duplicate output artifact bindings")
            validation.check(len(output_ids) == len(set(output_ids)), f"Receipt {receipt_id} contains duplicate output artifact IDs")
            validation.check(len(output_uris) == len(set(output_uris)), f"Receipt {receipt_id} contains duplicate output artifact URIs")
            validation.check(
                sum(output.get("itemCount", 0) for output in outputs) == receipt.get("work", {}).get("completed"),
                f"Receipt {receipt_id} output item counts do not reconcile to completed work",
            )
            for output in outputs:
                uri = output.get("artifactUri", "")
                relative = uri.removeprefix("package://") if uri.startswith("package://") else ""
                artifact_path = (ROOT / relative).resolve()
                validation.check(bool(relative) and artifact_path.is_file() and ROOT.resolve() in artifact_path.parents, f"Receipt {receipt_id} output URI does not resolve inside the package")
                if artifact_path.is_file() and ROOT.resolve() in artifact_path.parents:
                    expected_content_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                    validation.check(output.get("contentHash") == expected_content_hash, f"Receipt {receipt_id} output hash differs from {relative}")
                    selector = output.get("countSelector", {})
                    selector_kind = selector.get("kind") if isinstance(selector, dict) else None
                    selected_evidence_kinds = set(selector.get("evidenceKinds", [])) if isinstance(selector, dict) else set()
                    derived_count: int | None = None
                    if selector_kind == "document":
                        derived_count = 1
                    elif selector_kind == "control-document":
                        derived_count = 0
                    else:
                        try:
                            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
                            records = [row for row in artifact.get("records", []) if not selected_evidence_kinds or row.get("kind") in selected_evidence_kinds]
                            if selector_kind == "structure-assets":
                                derived_count = len(artifact.get("assets", []))
                            elif selector_kind == "evidence-records":
                                derived_count = len(records)
                            elif selector_kind == "evidence-assets":
                                derived_count = len({row.get("subject", {}).get("assetId") for row in records if row.get("subject", {}).get("assetId")})
                            elif selector_kind == "evidence-fields":
                                derived_count = sum(len((row.get("payload") or {}).get("fields", {})) for row in records)
                            elif selector_kind == "stage-items":
                                stage_output = next((row for row in artifact.get("outputs", []) if row.get("stageId") == stage_id), None)
                                derived_count = sum(1 for item in stage_output.get("items", []) if item.get("outcome") == "completed") if stage_output is not None else None
                            elif selector_kind == "profile-model-patterns":
                                derived_count = len(artifact.get("modelPatterns", []))
                            elif selector_kind == "profile-business-concepts":
                                model = artifact.get("businessModel", {})
                                derived_count = sum(len(model.get(group, [])) for group in ("domains", "entities", "events", "states", "processes", "measures", "dimensions", "metrics", "scenarios", "glossary"))
                            elif selector_kind == "profile-indexes":
                                derived_count = len(artifact.get("indexes", []))
                            elif selector_kind == "retrieval-products":
                                derived_count = len(artifact.get("items", [])) + len(artifact.get("conflicts", []))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            derived_count = None
                    validation.check(derived_count is not None, f"Receipt {receipt_id} output count selector {selector_kind} cannot be evaluated")
                    if derived_count is not None:
                        validation.check(output.get("itemCount") == derived_count, f"Receipt {receipt_id} output itemCount differs from derived {selector_kind} count")
        started = parse_time(row.get("startedAt"))
        completed = parse_time(row.get("completedAt"))
        if started is not None and completed is not None:
            validation.check(started <= completed, f"Run stage {stage_id} completes before it starts")
        if run_started is not None and started is not None:
            validation.check(run_started <= started, f"Run stage {stage_id} starts before the run")
        if run_completed is not None and completed is not None:
            validation.check(completed <= run_completed, f"Run stage {stage_id} completes after the run")
        if run.get("state") == "completed" and required_by_id.get(stage_id):
            validation.check(row.get("state") == "completed", f"Required stage {stage_id} did not complete in a completed run")
            validation.check(row.get("itemsCompleted", 0) > 0, f"Required stage {stage_id} completed zero work")

    for stage_id, dependencies in dependencies_by_id.items():
        started = parse_time(stages_by_id.get(stage_id, {}).get("startedAt"))
        for dependency_id in dependencies:
            dependency_completed = parse_time(stages_by_id.get(dependency_id, {}).get("completedAt"))
            if started is not None and dependency_completed is not None:
                validation.check(
                    dependency_completed <= started,
                    f"Run stage {stage_id} starts before dependency {dependency_id} completes",
                )

    boundary = run.get("sourceBoundary", {})
    boundary_opened = parse_time(boundary.get("openedAt"))
    boundary_verified = parse_time(boundary.get("verifiedAt"))
    open_completed = parse_time(stages_by_id.get("open-source-boundary", {}).get("completedAt"))
    discovery_started = parse_time(stages_by_id.get("discover-structure", {}).get("startedAt"))
    discovery_completed = parse_time(stages_by_id.get("discover-structure", {}).get("completedAt"))
    verification_started = parse_time(stages_by_id.get("verify-source-boundary", {}).get("startedAt"))
    verification_completed = parse_time(stages_by_id.get("verify-source-boundary", {}).get("completedAt"))
    indexing_started = parse_time(stages_by_id.get("build-indexes", {}).get("startedAt"))
    validation.check(boundary_opened == open_completed, "Source boundary openedAt differs from the opening-stage receipt time")
    validation.check(boundary_verified == verification_completed, "Source boundary verifiedAt differs from the verification-stage receipt time")
    validation.check(boundary_opening.get("recordType") == "opening", "Source boundary opening artifact has the wrong record type")
    validation.check(boundary_verification.get("recordType") == "verification", "Source boundary verification artifact has the wrong record type")
    for key in ("boundaryId", "runId", "sourceId", "sourceVersionCandidate", "connectorId", "connectorVersion", "connectorCapabilityHash", "authorizationScopeId", "policyHash", "mode", "openedAt", "openingTokens"):
        validation.check(boundary_opening.get(key) == boundary_verification.get(key), f"Source boundary verification {key} differs from its opening record")
    validation.check(boundary_opening.get("runId") == run.get("runId"), "Source boundary opening belongs to another run")
    validation.check(run.get("sourceVersionCandidate") == source_descriptor.get("registrationGeneration"), "Run source-version candidate differs from source registration generation")
    validation.check(boundary_opening.get("sourceVersionCandidate") == run.get("sourceVersionCandidate"), "Source boundary opening candidate differs from the run")
    validation.check(boundary_opening.get("boundaryId") == boundary.get("boundaryId"), "Run source-boundary ID differs from the immutable opening record")
    validation.check(boundary_opening.get("openedAt") == boundary.get("openedAt"), "Run source-boundary openedAt differs from the immutable opening record")
    validation.check(boundary_opening.get("openingTokens") == boundary.get("boundaryTokens"), "Run source-boundary tokens differ from the immutable opening record")
    validation.check(boundary_verification.get("sourceVersion") == run.get("sourceVersion"), "Source boundary verification version differs from the run")
    validation.check(boundary_verification.get("verifiedAt") == boundary.get("verifiedAt"), "Run source-boundary verifiedAt differs from the immutable verification record")
    validation.check(boundary_verification.get("consistencyStatus") == boundary.get("consistencyStatus"), "Run source-boundary status differs from the immutable verification record")
    if boundary.get("mode") in {"snapshot", "transaction"}:
        validation.check(boundary_verification.get("verificationTokens") == boundary_opening.get("openingTokens"), "Stable-handle boundary verification does not name the opened handle")
    try:
        import rfc8785  # type: ignore[import-not-found]
        import yaml  # type: ignore[import-not-found]
        discovery_limits = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))["discovery"]
        normalized_assets = []
        for asset in sorted(source_structure.get("assets", []), key=lambda row: row.get("assetId", "")):
            normalized_assets.append(
                {
                    "assetId": asset.get("assetId"),
                    "nativeName": asset.get("nativeName"),
                    "kind": asset.get("kind"),
                    "fields": [
                        {
                            "path": field.get("path"),
                            "physicalType": field.get("physicalType"),
                            "typeVariants": sorted(field.get("typeVariants", [])),
                            "nullable": field.get("nullable"),
                        }
                        for field in sorted(asset.get("fields", []), key=lambda row: row.get("path", ""))
                    ],
                    "constraints": sorted(asset.get("constraints", [])),
                }
            )
        structure_preimage = {
            "connectorId": source_structure.get("connectorId"),
            "connectorVersion": source_structure.get("connectorVersion"),
            "connectorCapabilityHash": source_structure.get("connectorCapabilityHash"),
            "assets": normalized_assets,
        }
        expected_structure_hash = hashlib.sha256(rfc8785.dumps(structure_preimage)).hexdigest()
        expected_source_version = f"sha256:{expected_structure_hash}"
        validation.check(source_structure.get("structureHash") == expected_structure_hash, "Source structure hash is not derivable from canonical bounded structure")
        validation.check(source_structure.get("sourceVersion") == expected_source_version, "Source version is not derived from the canonical structure hash")
        validation.check(source_structure.get("sourceVersion") == run.get("sourceVersion"), "Run sourceVersion differs from the bounded structure snapshot")
        validation.check(source_structure.get("boundaryId") == boundary_opening.get("boundaryId"), "Source structure snapshot belongs to another boundary")
        validation.check(source_structure.get("sourceVersionCandidate") == run.get("sourceVersionCandidate"), "Source structure candidate differs from the run")
        for key in ("runId", "sourceId", "connectorId", "connectorVersion", "connectorCapabilityHash", "authorizationScopeId"):
            validation.check(source_structure.get(key) == run.get(key), f"Source structure {key} differs from the run")
        structure_assets = [row for row in source_structure.get("assets", []) if isinstance(row, dict)]
        validation.check(len(structure_assets) <= discovery_limits["maximumAssetsPerRun"], "Source structure exceeds discovery maximumAssetsPerRun")
        for structure_asset in structure_assets:
            validation.check(len(structure_asset.get("fields", [])) <= discovery_limits["maximumFieldsPerAsset"], f"Source structure asset {structure_asset.get('assetId')} exceeds discovery maximumFieldsPerAsset")
        structure_asset_ids = [row.get("assetId") for row in structure_assets]
        validation.check(len(structure_asset_ids) == len(set(structure_asset_ids)), "Source structure contains duplicate asset IDs")
        validation.check(set(structure_asset_ids) == set(asset_ids), "Source structure assets differ from the served profile")
        profile_assets = {row.get("assetId"): row for row in profile.get("assets", []) if isinstance(row, dict)}
        for structure_asset in structure_assets:
            asset_id = structure_asset.get("assetId")
            profile_asset = profile_assets.get(asset_id, {})
            validation.check(structure_asset.get("nativeName") == profile_asset.get("name"), f"Source structure asset {asset_id} name differs from the served profile")
            validation.check(structure_asset.get("kind") == profile_asset.get("kind"), f"Source structure asset {asset_id} kind differs from the served profile")
            structure_fields = [row for row in structure_asset.get("fields", []) if isinstance(row, dict)]
            structure_field_paths = [row.get("path") for row in structure_fields]
            validation.check(len(structure_field_paths) == len(set(structure_field_paths)), f"Source structure asset {asset_id} contains duplicate field paths")
            profile_fields = {row.get("path"): row for row in profile_asset.get("fields", []) if isinstance(row, dict)}
            validation.check(set(structure_field_paths) == set(profile_fields), f"Source structure asset {asset_id} fields differ from the served profile")
            for structure_field in structure_fields:
                field_path = structure_field.get("path")
                profile_field = profile_fields.get(field_path, {})
                validation.check(structure_field.get("physicalType") == profile_field.get("physicalType"), f"Source structure field {asset_id}.{field_path} type differs from the served profile")
                validation.check(sorted(structure_field.get("typeVariants", [])) == sorted(profile_field.get("typeVariants", [])), f"Source structure field {asset_id}.{field_path} variants differ from the served profile")
        validation.check(boundary_verification.get("structureHash") == source_structure.get("structureHash"), "Boundary verification structure hash differs from bounded discovery")
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing for source-version derivation ({exc})")
    if boundary_opened is not None and discovery_started is not None:
        validation.check(boundary_opened <= discovery_started, "Structure discovery starts before the source boundary opens")
    if discovery_completed is not None and verification_started is not None:
        validation.check(discovery_completed <= verification_started, "Source boundary verification starts before bounded discovery completes")
    if boundary_verified is not None and indexing_started is not None:
        validation.check(boundary_verified <= indexing_started, "Index construction starts before source-boundary verification completes")

    validation.check(total_completed > 0, "A terminal run example must record nonzero completed work")
    coverage = run.get("coverage", {})
    validation.check(
        coverage.get("assetsDiscovered") == sum(coverage.get(key, 0) for key in ("assetsCompleted", "assetsFailed", "assetsSkipped", "assetsUnavailable", "assetsNotRun", "assetsDeferred")),
        "Run asset coverage does not reconcile to discovered assets",
    )
    validation.check(coverage.get("assetsAttempted") == coverage.get("assetsCompleted", 0) + coverage.get("assetsFailed", 0), "Run asset attempts do not reconcile")
    validation.check(
        coverage.get("fieldsDiscovered") == sum(coverage.get(key, 0) for key in ("fieldsProfiled", "fieldsFailed", "fieldsSkipped", "fieldsUnavailable", "fieldsNotRun", "fieldsDeferred")),
        "Run field coverage does not reconcile to discovered fields",
    )
    validation.check(coverage.get("fieldsAttempted") == coverage.get("fieldsProfiled", 0) + coverage.get("fieldsFailed", 0), "Run field attempts do not reconcile")
    validation.check(coverage.get("relationshipsValidated", 0) <= coverage.get("relationshipsConsidered", 0), "Run validates more relationships than it considered")
    validation.check(referenced_receipts == set(receipt_ids), "Stage receipt bundle contains unreferenced or multiply-substituted receipts")
    try:
        import rfc8785  # type: ignore[import-not-found]
        expected_bundle_hash = hashlib.sha256(rfc8785.dumps({key: value for key, value in receipt_bundle.items() if key not in {"bundleHash", "signature"}})).hexdigest()
        validation.check(receipt_bundle.get("hashAlgorithm") == "sha256-jcs", "Stage receipt bundle declares no canonical hash algorithm")
        validation.check(receipt_bundle.get("bundleHash") == expected_bundle_hash, "Stage receipt bundle hash mismatch")
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing ({exc})")
    if run.get("state") == "completed":
        validation.check(run.get("sourceBoundary", {}).get("consistencyStatus") == "consistent", "A completed run must have a consistent source boundary")
        validation.check(
            bool(run.get("manifestVersion")) and bool(run.get("projectionId")) and bool(run.get("evidenceCutoff")),
            "A completed run must pin its projection coordinate",
        )


SECRET_LIKE_PATTERNS = [
    r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|account[_-]?key|client[_-]?secret|connection[_-]?string|private[_-]?key|signature|sig)\b\s*[:=]",
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}",
    r"(?i)\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
    r"(?i)\b(?:sk|rk|pat|oauth|session|credential)[_-](?:live|prod|test|key|token)[_-][A-Za-z0-9_-]{16,}\b",
]


def has_high_entropy_token(value: str) -> bool:
    for candidate in re.findall(r"[A-Za-z0-9+/=_-]{24,}", value):
        if re.fullmatch(r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}", candidate):
            continue
        if re.fullmatch(r"[a-fA-F0-9]{32,128}", candidate):
            probabilities = [candidate.count(character) / len(candidate) for character in set(candidate)]
            entropy = -sum(probability * math.log2(probability) for probability in probabilities)
            if len(set(candidate)) >= 8 and entropy >= 3.5:
                return True
        if len(set(candidate)) < 8:
            continue
        character_classes = sum(
            bool(re.search(pattern, candidate))
            for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+/=_-]")
        )
        if character_classes < 3:
            continue
        probabilities = [candidate.count(character) / len(candidate) for character in set(candidate)]
        entropy = -sum(probability * math.log2(probability) for probability in probabilities)
        if entropy >= 4.0:
            return True
    return False


def detects_secret_like_input(value: str) -> bool:
    return any(re.search(pattern, value) for pattern in SECRET_LIKE_PATTERNS) or has_high_entropy_token(value)


DIRECT_IDENTIFIER_PATTERNS = [
    r"(?i)(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])",
    r"(?<!\d)(?:\+?[1-9]\d{0,2}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\d)",
]


def contains_direct_identifier(value: str) -> bool:
    return any(re.search(pattern, value) for pattern in DIRECT_IDENTIFIER_PATTERNS)


def validate_security_fixtures(validation: Validation) -> None:
    cases = load_json("security/registration-negative-cases.json", validation)
    schema = load_json("contracts/source-registration-request.schema.json", validation)
    baseline = load_json("examples/source-registration-request.json", validation)
    if not all(isinstance(value, dict) for value in (cases, schema, baseline)):
        return

    rows = [row for row in cases.get("cases", []) if isinstance(row, dict)]
    benign_rows = [row for row in cases.get("benignCases", []) if isinstance(row, dict)]
    validation.check(len(rows) >= 10, "Registration negative-case corpus is too small to be meaningful")
    validation.check(len(benign_rows) >= 3, "Registration secret-scan corpus has too few benign controls")
    validation.check(
        len({row.get("caseId") for row in rows}) == len(rows),
        "Registration negative cases contain duplicate case IDs",
    )

    locator_pattern = schema.get("properties", {}).get("locator", {}).get("properties", {}).get("resource", {}).get("pattern")
    credential_schema = schema.get("properties", {}).get("credentialRef", {}).get("properties", {}).get("referenceId", {})
    validation.check(bool(locator_pattern), "The registration contract does not constrain locator resources")
    validation.check(credential_schema.get("format") == "uuid", "The registration contract does not require an opaque credential identifier")

    for row in rows:
        target = row.get("targetPath", "")
        value = row.get("value", "")
        case_id = row.get("caseId")
        validation.check(bool(row.get("expectedReasonCode")), f"Negative case {case_id} declares no expected reason code")
        secret_like = detects_secret_like_input(value)
        validation.check(
            secret_like == (row.get("expectedReasonCode") == "SECRET_LIKE_INPUT"),
            f"Negative case {case_id} disagrees with the secret-scan rule about its own value",
        )
        locator_rejected = bool(locator_pattern) and re.fullmatch(locator_pattern, value) is None
        try:
            uuid.UUID(value)
            credential_rejected = False
        except ValueError:
            credential_rejected = True
        validation.check(
            secret_like or locator_rejected or credential_rejected,
            f"Negative case {case_id} is rejected by no declared rule",
        )
        if target == "locator.resource" and locator_pattern:
            validation.check(
                re.fullmatch(locator_pattern, value) is None,
                f"Negative locator case {row.get('caseId')} is accepted by the contract pattern",
            )
        if target == "credentialRef.referenceId":
            try:
                uuid.UUID(value)
                accepted = True
            except ValueError:
                accepted = False
            validation.check(not accepted, f"Negative credential case {row.get('caseId')} is accepted by the contract")

    for row in benign_rows:
        validation.check(bool(row.get("caseId")), "A benign secret-scan control has no case ID")
        validation.check(
            not detects_secret_like_input(row.get("value", "")),
            f"Benign case {row.get('caseId')} is falsely classified as secret-like",
        )

    for value in ("169.254.169.254/path", "127.0.0.1/path"):
        host = value.split("/", 1)[0]
        try:
            address = ipaddress.ip_address(host)
            validation.check(
                address.is_private or address.is_loopback or address.is_link_local,
                f"Fixture {value} is not a recognized internal address",
            )
        except ValueError:
            validation.check(False, f"Fixture {value} is not a parsable address literal")


def validate_features_and_traceability(validation: Validation) -> None:
    scenarios_by_feature = parse_features(validation)
    tags_by_feature = parse_feature_tags(validation)
    outcomes_by_feature = parse_feature_outcomes(validation)
    validation.check(len(scenarios_by_feature) >= 7, "Expected at least seven BDD feature files")
    total_scenarios = sum(len(names) for names in scenarios_by_feature.values())
    validation.check(total_scenarios >= 50, f"Expected at least 50 BDD scenarios, found {total_scenarios}")

    catalog = load_json("requirements/catalog.json", validation)
    if not isinstance(catalog, dict):
        return scenarios_by_feature
    requirements = catalog.get("requirements", [])
    validation.check(len(requirements) >= 30, f"Expected at least 30 requirements, found {len(requirements)}")
    ids = [item.get("id") for item in requirements if isinstance(item, dict)]
    validation.check(len(ids) == len(set(ids)), "Requirement IDs are not unique")

    referenced: set[str] = set()
    semantic_bindings: list[dict[str, Any]] = []
    for requirement in requirements:
        if not isinstance(requirement, dict):
            validation.check(False, "Requirement catalog contains a non-object item")
            continue
        requirement_id = requirement.get("id", "<missing>")
        validation.check(bool(requirement.get("statement")), f"Requirement {requirement_id} has no statement")
        acceptance = requirement.get("acceptance", [])
        validation.check(bool(acceptance), f"Requirement {requirement_id} has no acceptance criteria")
        acceptance_ids = [criterion.get("id") for criterion in acceptance if isinstance(criterion, dict)]
        validation.check(len(acceptance_ids) == len(acceptance), f"Requirement {requirement_id} contains a non-object acceptance criterion")
        validation.check(len(acceptance_ids) == len(set(acceptance_ids)), f"Requirement {requirement_id} contains duplicate acceptance IDs")
        for criterion in acceptance:
            if isinstance(criterion, dict):
                validation.check(bool(criterion.get("text")), f"Requirement {requirement_id} criterion {criterion.get('id')} has no text")
        bdd_refs = requirement.get("bdd", [])
        validation.check(len(bdd_refs) > 0, f"Requirement {requirement_id} has no BDD references")
        mapping_pairs = [
            (mapping.get("acceptanceId"), mapping.get("scenarioRef"))
            for mapping in bdd_refs
            if isinstance(mapping, dict)
        ]
        validation.check(len(mapping_pairs) == len(bdd_refs), f"Requirement {requirement_id} contains a non-object BDD mapping")
        validation.check(len(mapping_pairs) == len(set(mapping_pairs)), f"Requirement {requirement_id} contains duplicate BDD mappings")
        mapped_ids = {acceptance_id for acceptance_id, _ in mapping_pairs}
        validation.check(
            mapped_ids == set(acceptance_ids),
            f"Requirement {requirement_id} acceptance mapping differs: missing={sorted(set(acceptance_ids) - mapped_ids)}, extra={sorted(mapped_ids - set(acceptance_ids))}",
        )
        for acceptance_id, reference in mapping_pairs:
            validation.check(acceptance_id in acceptance_ids, f"Requirement {requirement_id} maps unknown acceptance criterion {acceptance_id}")
            if not isinstance(reference, str):
                validation.check(False, f"Invalid BDD reference on {requirement_id}: {reference}")
                continue
            if ":" not in reference:
                validation.check(False, f"Invalid BDD reference on {requirement_id}: {reference}")
                continue
            feature_name, scenario_name = reference.split(":", 1)
            names = scenarios_by_feature.get(feature_name)
            validation.check(names is not None, f"BDD feature not found for {requirement_id}: {feature_name}")
            if names is not None:
                validation.check(scenario_name in names, f"BDD scenario not found for {requirement_id}: {reference}")
                if scenario_name in names:
                    expected_tag = f"@{requirement_id}-{acceptance_id}"
                    actual_tags = tags_by_feature.get(feature_name, {}).get(scenario_name, set())
                    validation.check(expected_tag in actual_tags, f"BDD scenario {reference} lacks semantic criterion tag {expected_tag}")
                    acceptance_text = next(
                        (criterion.get("text") for criterion in acceptance if criterion.get("id") == acceptance_id),
                        None,
                    )
                    outcome_steps = outcomes_by_feature.get(feature_name, {}).get(scenario_name, [])
                    validation.check(bool(outcome_steps), f"BDD scenario {reference} has no outcome steps for semantic binding")
                    semantic_bindings.append(
                        {
                            "acceptanceId": f"{requirement_id}-{acceptance_id}",
                            "acceptanceText": acceptance_text,
                            "scenarioRef": reference,
                            "outcomeSteps": outcome_steps,
                        }
                    )
                    referenced.add(reference)

    orphans = {
        f"{feature}:{name}"
        for feature, names in scenarios_by_feature.items()
        for name in names
    } - referenced
    supplementary_rows = [row for row in catalog.get("supplementaryScenarios", []) if isinstance(row, dict)]
    supplementary = [row.get("scenarioRef") for row in supplementary_rows]
    validation.check(len(supplementary) == len(set(supplementary)), "Supplementary scenario inventory contains duplicates")
    validation.check(set(supplementary) == orphans, f"Supplementary scenario inventory differs from untraced scenarios: missing={sorted(orphans - set(supplementary))}, extra={sorted(set(supplementary) - orphans)}")
    for row in supplementary_rows:
        validation.check(bool(row.get("rationale")), f"Supplementary scenario {row.get('scenarioRef')} has no rationale")
    try:
        import rfc8785  # type: ignore[import-not-found]
        semantic_bindings.sort(key=lambda row: (row["acceptanceId"], row["scenarioRef"]))
        expected_binding_hash = hashlib.sha256(rfc8785.dumps(semantic_bindings)).hexdigest()
        validation.check(catalog.get("semanticBindingAlgorithm") == "sha256-jcs-acceptance-outcomes-v1", "Requirement catalog declares an unsupported semantic binding algorithm")
        validation.check(catalog.get("semanticBindingHash") == expected_binding_hash, f"Requirement semantic binding hash mismatch: expected {expected_binding_hash}")
    except ImportError as exc:
        validation.check(False, f"Canonical JSON library missing for semantic binding verification ({exc})")
    return scenarios_by_feature


def validate_standards(validation: Validation) -> None:
    try:
        import yaml  # type: ignore[import-not-found]
        from jsonschema import Draft202012Validator, FormatChecker
        from openapi_spec_validator import validate as validate_openapi
        from openapi_spec_validator.readers import read_from_filename
        from referencing import Registry, Resource
    except ImportError as exc:
        validation.check(
            False,
            f"Pinned validation dependency missing ({exc}); run: python -m pip install -r requirements-validation.txt",
        )
        return

    schema_paths = sorted((ROOT / "contracts").glob("*.schema.json")) + [
        ROOT / "requirements" / "catalog.schema.json"
    ]
    schemas: list[tuple[Path, dict[str, Any]]] = []
    for path in schema_paths:
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            schemas.append((path, schema))
            validation.check(True, f"Schema is valid: {path.relative_to(ROOT)}")
        except Exception as exc:  # noqa: BLE001 - aggregate contract failures
            validation.check(False, f"JSON Schema meta-validation failed for {path.relative_to(ROOT)}: {exc}")

    registry = Registry().with_resources([
        (schema["$id"], Resource.from_contents(schema))
        for _, schema in schemas
        if "$id" in schema
    ])

    for instance_path, schema_path in EXAMPLE_SCHEMA_PAIRS:
        try:
            instance = json.loads((ROOT / instance_path).read_text(encoding="utf-8"))
            schema = json.loads((ROOT / schema_path).read_text(encoding="utf-8"))
            errors = list(Draft202012Validator(
                schema,
                registry=registry,
                format_checker=FormatChecker(),
            ).iter_errors(instance))
            validation.check(
                not errors,
                f"Standards validation failed for {instance_path}: "
                + "; ".join(error.message for error in errors),
            )
        except Exception as exc:  # noqa: BLE001
            validation.check(False, f"Standards validation could not run for {instance_path}: {exc}")

    try:
        specification, base_uri = read_from_filename(str(ROOT / "contracts" / "api.openapi.yaml"))
        validate_openapi(specification, base_uri=base_uri)
        validation.check(True, "OpenAPI contract passed standards validation")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"OpenAPI validation failed: {exc}")


def validate_links(validation: Validation) -> None:
    link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for path in sorted(ROOT.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for target in link_pattern.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            raw_target = target.split("#", 1)[0].replace("%20", " ")
            if not raw_target:
                continue
            destination = (path.parent / raw_target).resolve()
            validation.check(destination.exists(), f"Broken relative link in {path.relative_to(ROOT)}: {target}")


def validate_prompt_contracts(validation: Validation) -> None:
    for path in sorted((ROOT / "prompts").glob("*.prompt.md")):
        text = path.read_text(encoding="utf-8")
        validation.check(
            re.search(r"^inputEncoding:\s*base64-rfc8785-json$", text, re.MULTILINE) is not None,
            f"Prompt {path.name} does not require base64-only input transport",
        )
        validation.check(
            text.count("{{INPUT_PACK_BASE64}}") == 1,
            f"Prompt {path.name} must contain exactly one base64 input placeholder",
        )
        unsafe_placeholders = [
            value
            for value in re.findall(r"\{\{([^}]+)\}\}", text)
            if value != "INPUT_PACK_BASE64"
        ]
        validation.check(
            not unsafe_placeholders,
            f"Prompt {path.name} contains non-base64 input placeholders: {unsafe_placeholders}",
        )
        for field in ("inputContract", "outputContract"):
            match = re.search(rf"^{field}:\s*(.+)$", text, re.MULTILINE)
            validation.check(match is not None, f"Missing {field} in {path.relative_to(ROOT)}")
            if match is None:
                continue
            reference = match.group(1).strip()
            file_part, _, fragment = reference.partition("#")
            target = (path.parent / file_part).resolve()
            validation.check(target.is_file(), f"Prompt contract file not found: {path.name}:{reference}")
            if not target.is_file():
                continue
            try:
                schema = json.loads(target.read_text(encoding="utf-8"))
                resolved = schema if not fragment else resolve_pointer(schema, f"#/{fragment.lstrip('/')}")
                validation.check(isinstance(resolved, dict), f"Prompt contract fragment not found: {path.name}:{reference}")
            except Exception as exc:  # noqa: BLE001
                validation.check(False, f"Prompt contract could not be parsed: {path.name}:{reference}: {exc}")


def validate_pipeline_registries(validation: Validation) -> None:
    stages = load_json("pipeline/stages.json", validation)
    run_schema = load_json("contracts/profiling-run.schema.json", validation)
    matrix = load_json("pipeline/capability-matrix.json", validation)
    source_schema = load_json("contracts/source-descriptor.schema.json", validation)
    if not all(isinstance(value, dict) for value in (stages, run_schema, matrix, source_schema)):
        return

    stage_rows = stages.get("stages", [])
    stage_ids = [row.get("id") for row in stage_rows if isinstance(row, dict)]
    validation.check(len(stage_ids) == 19, f"Canonical pipeline must contain 19 stages, found {len(stage_ids)}")
    validation.check(len(stage_ids) == len(set(stage_ids)), "Canonical stage IDs are not unique")
    orders = [row.get("order") for row in stage_rows if isinstance(row, dict)]
    validation.check(orders == list(range(1, len(stage_rows) + 1)), "Canonical stage order is not contiguous")
    stage_set = set(stage_ids)
    for row in stage_rows:
        if not isinstance(row, dict):
            continue
        for dependency in row.get("dependencies", []):
            validation.check(dependency in stage_set, f"Stage {row.get('id')} has unknown dependency {dependency}")
            if dependency in stage_set:
                validation.check(stage_ids.index(dependency) < stage_ids.index(row.get("id")), f"Stage {row.get('id')} depends on a later stage {dependency}")

    schema_stage_ids = set(
        run_schema.get("$defs", {}).get("stage", {}).get("properties", {}).get("stageId", {}).get("enum", [])
    )
    validation.check(schema_stage_ids == stage_set, "Run-schema stage IDs differ from pipeline/stages.json")
    prefix_items = run_schema.get("properties", {}).get("stages", {}).get("prefixItems", [])
    for index, row in enumerate(stage_rows):
        positional = prefix_items[index].get("allOf", [None, {}])[1].get("properties", {}) if index < len(prefix_items) else {}
        validation.check(positional.get("stageId", {}).get("const") == row.get("id"), f"Run positional stage {index + 1} differs from the pipeline registry")
        validation.check(positional.get("required", {}).get("const") == row.get("required"), f"Run stage {row.get('id')} schema requiredness differs from the pipeline registry")

    capability_ids = {row.get("id") for row in matrix.get("capabilities", []) if isinstance(row, dict)}
    source_capabilities = set(
        source_schema.get("properties", {}).get("effectiveCapabilities", {}).get("items", {}).get("enum", [])
    )
    validation.check(capability_ids == source_capabilities, "Source capability enum differs from capability matrix")
    authorization_ops = set(matrix.get("authorizationOperations", []))
    source_authorization_ops = set(
        source_schema.get("properties", {}).get("authorizationScope", {}).get("properties", {}).get("authorizedOperations", {}).get("items", {}).get("enum", [])
    )
    validation.check(authorization_ops == source_authorization_ops, "Authorization-operation enum differs from capability matrix")

    documented = re.findall(
        r"^\|\s*(\d+)\.\s*[^|]+\|[^|]*\|[^|]*\|\s*([^|]+?)\s*\|$",
        (ROOT / "docs" / "03-pipeline-and-algorithms.md").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    validation.check(len(documented) == len(stage_rows), f"The documented stage table lists {len(documented)} stages, not {len(stage_rows)}")
    for order, requiredness in documented:
        row = stage_rows[int(order) - 1] if int(order) <= len(stage_rows) else {}
        expected = "Yes" if row.get("required") else "Conditional"
        validation.check(
            requiredness == expected,
            f"Documented stage {order} is '{requiredness}' but pipeline/stages.json declares '{expected}'",
        )


def collect_key_values(value: Any, key_name: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == key_name:
                found.append(child)
            found.extend(collect_key_values(child, key_name))
    elif isinstance(value, list):
        for child in value:
            found.extend(collect_key_values(child, key_name))
    return found


def validate_example_references(validation: Validation) -> None:
    bundle = load_json("examples/evidence-bundle.json", validation)
    profile = load_json("examples/profile-manifest.json", validation)
    capability = load_json("examples/capability-manifest.json", validation)
    relationship_schema = load_json("contracts/relationship-validation.schema.json", validation)
    if not all(isinstance(value, dict) for value in (bundle, profile, capability, relationship_schema)):
        return

    records = bundle.get("records", [])
    evidence_by_id = {record.get("evidenceId"): record for record in records if isinstance(record, dict)}
    validation.check(len(evidence_by_id) == len(records), "Evidence bundle contains duplicate or missing evidence IDs")

    all_refs: list[str] = []
    for root in (profile, capability):
        for values in collect_key_values(root, "evidenceRefs"):
            if isinstance(values, list):
                all_refs.extend(item for item in values if isinstance(item, str))
        for value in collect_key_values(root, "validationEvidenceRef"):
            if isinstance(value, str):
                all_refs.append(value)
    for evidence_id in all_refs:
        validation.check(evidence_id in evidence_by_id, f"Manifest references missing evidence {evidence_id}")

    for record in records:
        if not isinstance(record, dict):
            continue
        validation.check(record.get("subject", {}).get("versionId") == record.get("sourceVersion"), f"Evidence {record.get('evidenceId')} subject version differs from its sourceVersion")
        validation.check(record.get("validity", {}).get("schemaVersion") == record.get("sourceVersion"), f"Evidence {record.get('evidenceId')} validity schemaVersion differs from its sourceVersion")
        for evidence_id in record.get("provenance", {}).get("inputEvidenceIds", []):
            validation.check(evidence_id in evidence_by_id, f"Evidence {record.get('evidenceId')} depends on missing evidence {evidence_id}")
        if record.get("kind") == "relationship-validation":
            errors: list[str] = []
            validate_schema(
                record.get("payload"),
                relationship_schema,
                relationship_schema,
                "$",
                errors,
                ROOT / "contracts" / "relationship-validation.schema.json",
            )
            validation.check(not errors, "Relationship evidence payload is invalid: " + "; ".join(errors))
            payload = record.get("payload") or {}
            left_scope = payload.get("left", {}).get("authorizationScopeId")
            right_scope = payload.get("right", {}).get("authorizationScopeId")
            derived_cross_scope = left_scope != right_scope
            validation.check(
                payload.get("crossScope") == derived_cross_scope,
                f"Relationship {payload.get('relationshipValidationId')} declares crossScope={payload.get('crossScope')} but its endpoint scopes derive {derived_cross_scope}",
            )
            if derived_cross_scope:
                grant = payload.get("crossScopeAuthorizationReceipt")
                validation.check(
                    isinstance(grant, dict),
                    f"Cross-scope relationship {payload.get('relationshipValidationId')} has no authorization receipt",
                )
                if isinstance(grant, dict):
                    validation.check(grant.get("relationshipValidationId") == payload.get("relationshipValidationId"), "Cross-scope grant names a different relationship validation")
                    validation.check(grant.get("left") == {key: payload.get("left", {}).get(key) for key in ("sourceId", "sourceVersion", "authorizationScopeId", "revocationEpoch")}, "Cross-scope grant left endpoint differs from the relationship")
                    validation.check(grant.get("right") == {key: payload.get("right", {}).get(key) for key in ("sourceId", "sourceVersion", "authorizationScopeId", "revocationEpoch")}, "Cross-scope grant right endpoint differs from the relationship")
                    validation.check(grant.get("policyHash") == record.get("policyHash"), "Cross-scope grant policy differs from its evidence record")
            else:
                validation.check(payload.get("crossScopeAuthorizationReceipt") is None, f"Same-scope relationship {payload.get('relationshipValidationId')} carries an unnecessary cross-scope grant")
                validation.check(
                    record.get("authorizationScopeId") == left_scope,
                    f"Relationship {payload.get('relationshipValidationId')} endpoint scope differs from its evidence record scope",
                )

    assets = {asset.get("assetId"): asset for asset in profile.get("assets", []) if isinstance(asset, dict)}
    relationships = {rel.get("relationshipId"): rel for rel in profile.get("relationships", []) if isinstance(rel, dict)}
    validation.check(len(assets) == len(profile.get("assets", [])), "Profile contains duplicate or missing asset IDs")
    validation.check(len(relationships) == len(profile.get("relationships", [])), "Profile contains duplicate or missing relationship IDs")

    for relationship in relationships.values():
        reference = relationship.get("validationEvidenceRef")
        if reference is not None:
            record = evidence_by_id.get(reference)
            validation.check(record is not None, f"Relationship {relationship.get('relationshipId')} cites missing validation evidence")
            if record is not None:
                validation.check(
                    record.get("kind") == "relationship-validation",
                    f"Relationship {relationship.get('relationshipId')} cites {record.get('kind')} evidence instead of relationship-validation",
                )
                payload = record.get("payload") or {}
                for side in ("left", "right"):
                    validation.check(
                        payload.get(side, {}).get("assetId") == relationship.get(side, {}).get("assetId"),
                        f"Relationship {relationship.get('relationshipId')} {side} endpoint differs from its validation evidence",
                    )
                    validation.check(
                        payload.get(side, {}).get("paths") == relationship.get(side, {}).get("paths"),
                        f"Relationship {relationship.get('relationshipId')} {side} paths differ from its validation evidence",
                    )
                expected_status = {
                    "supported": "validated",
                    "rejected": "rejected",
                    "insufficient-support": "hypothesis",
                    "unavailable": "unavailable",
                }.get(payload.get("validationOutcome"))
                validation.check(relationship.get("validationStatus") == expected_status, f"Relationship {relationship.get('relationshipId')} status differs from validation evidence")
                validation.check(relationship.get("kind") == payload.get("relationshipKind"), f"Relationship {relationship.get('relationshipId')} kind differs from validation evidence")
                validation.check(relationship.get("predicates") == payload.get("predicates"), f"Relationship {relationship.get('relationshipId')} predicates differ from validation evidence")
                validation.check(relationship.get("normalization") == payload.get("normalization"), f"Relationship {relationship.get('relationshipId')} normalization differs from validation evidence")
                validation.check(relationship.get("cardinality") == payload.get("cardinality", {}).get("relationshipType"), f"Relationship {relationship.get('relationshipId')} cardinality differs from validation evidence")
                validation.check(relationship.get("confidence") == payload.get("confidence"), f"Relationship {relationship.get('relationshipId')} confidence differs from validation evidence")
                validation.check(relationship.get("validationBasis") == payload.get("validator", {}).get("basis"), f"Relationship {relationship.get('relationshipId')} basis differs from validation evidence")
                validation.check(relationship.get("validationExact") == payload.get("validator", {}).get("exact"), f"Relationship {relationship.get('relationshipId')} exactness differs from validation evidence")
                validation.check(relationship.get("validationPlanHash") == payload.get("validator", {}).get("planHash"), f"Relationship {relationship.get('relationshipId')} plan hash differs from validation evidence")
                validation.check(relationship.get("recommendedOperation") == payload.get("recommendedOperation"), f"Relationship {relationship.get('relationshipId')} recommended operation differs from validation evidence")
                expected_coverage = {
                    "left": payload.get("coverage", {}).get("leftCoverage"),
                    "right": payload.get("coverage", {}).get("rightCoverage"),
                    "matches": payload.get("coverage", {}).get("matchingKeys"),
                    "confidenceBound": payload.get("coverage", {}).get("confidenceBound"),
                    "method": payload.get("validator", {}).get("method"),
                }
                validation.check(relationship.get("coverage") == expected_coverage, f"Relationship {relationship.get('relationshipId')} coverage differs from validation evidence")
                predicate_count = len(payload.get("predicates", []))
                normalization_indices = [row.get("predicateIndex") for row in payload.get("normalization", []) if isinstance(row, dict)]
                validation.check(sorted(normalization_indices) == list(range(predicate_count)), f"Relationship {relationship.get('relationshipId')} normalization does not cover each predicate exactly once")
                for index, predicate in enumerate(payload.get("predicates", [])):
                    normalization = next((row for row in payload.get("normalization", []) if row.get("predicateIndex") == index), None)
                    validation.check(normalization is not None, f"Relationship {relationship.get('relationshipId')} predicate {index} has no normalization")
                    if normalization is not None and normalization.get("family") == "exact":
                        validation.check(normalization.get("leftExpression") == predicate.get("leftPath"), f"Relationship {relationship.get('relationshipId')} exact left normalization differs from predicate path")
                        validation.check(normalization.get("rightExpression") == predicate.get("rightPath"), f"Relationship {relationship.get('relationshipId')} exact right normalization differs from predicate path")
        elif relationship.get("validationStatus") in {"validated", "rejected", "unavailable"}:
            validation.check(False, f"Relationship {relationship.get('relationshipId')} status requires validation evidence")

    for relationship in relationships.values():
        for side in ("left", "right"):
            endpoint = relationship.get(side, {})
            asset_id = endpoint.get("assetId")
            validation.check(asset_id in assets, f"Relationship {relationship.get('relationshipId')} references missing asset {asset_id}")
            if asset_id in assets:
                field_paths = {field.get("path") for field in assets[asset_id].get("fields", []) if isinstance(field, dict)}
                for field_path in endpoint.get("paths", []):
                    validation.check(field_path in field_paths, f"Relationship {relationship.get('relationshipId')} references missing path {asset_id}.{field_path}")

    for asset_ids in collect_key_values(profile.get("businessModel", {}), "assetIds") + collect_key_values(profile.get("businessModel", {}), "requiredAssetIds"):
        if isinstance(asset_ids, list):
            for asset_id in asset_ids:
                validation.check(asset_id in assets, f"Business model references missing asset {asset_id}")
    for relationship_ids in collect_key_values(profile.get("businessModel", {}), "requiredRelationshipIds"):
        if isinstance(relationship_ids, list):
            for relationship_id in relationship_ids:
                validation.check(relationship_id in relationships, f"Business model references missing relationship {relationship_id}")

    for item in capability.get("capabilities", []):
        for asset_id in item.get("requiredAssets", []):
            validation.check(asset_id in assets, f"Capability references missing asset {asset_id}")
        for relationship_id in item.get("requiredRelationships", []):
            validation.check(relationship_id in relationships, f"Capability references missing relationship {relationship_id}")

    for asset in profile.get("assets", []):
        validation.check(asset.get("sourceId") == profile.get("sourceId"), f"Asset {asset.get('assetId')} sourceId differs from profile manifest")
        validation.check(
            asset.get("authorizationScopeId") == profile.get("authorizationScopeId"),
            f"Asset {asset.get('assetId')} authorization scope differs from profile manifest",
        )

    for relationship in relationships.values():
        for side in ("left", "right"):
            endpoint = relationship.get(side, {})
            validation.check(
                endpoint.get("sourceId") == profile.get("sourceId"),
                f"Relationship {relationship.get('relationshipId')} {side} endpoint sourceId differs from profile manifest",
            )
            validation.check(
                endpoint.get("sourceVersion") == profile.get("sourceVersion"),
                f"Relationship {relationship.get('relationshipId')} {side} endpoint sourceVersion differs from profile manifest",
            )
            validation.check(
                endpoint.get("authorizationScopeId") == profile.get("authorizationScopeId"),
                f"Relationship {relationship.get('relationshipId')} {side} endpoint authorization scope differs from profile manifest",
            )

    try:
        import yaml  # type: ignore[import-not-found]
        semantic_taxonomy = yaml.safe_load((ROOT / "taxonomies" / "semantic-roles.yaml").read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to read semantic role taxonomy: {exc}")
        semantic_taxonomy = {}
    field_roles = set(semantic_taxonomy.get("fieldRoles", []))
    asset_roles = set(semantic_taxonomy.get("assetRoles", []))
    relationship_kinds = set(semantic_taxonomy.get("relationshipKinds", []))
    required_families = {"missingness", "cardinality", "distribution", "format", "temporal", "outlier", "nesting"}
    for asset in assets.values():
        validation.check(asset.get("role") in asset_roles, f"Asset {asset.get('assetId')} role is not in the semantic taxonomy")
        for field in asset.get("fields", []):
            validation.check(set(field.get("semanticRoles", [])) <= field_roles, f"Field {asset.get('assetId')}.{field.get('path')} uses unknown semantic roles")
            statistics = field.get("statistics", {})
            families = [row.get("family") for row in statistics.get("families", []) if isinstance(row, dict)]
            validation.check(len(families) == len(set(families)), f"Field {asset.get('assetId')}.{field.get('path')} repeats a statistic family")
            validation.check(set(families) == required_families, f"Field {asset.get('assetId')}.{field.get('path')} does not account for every statistic family")
            validation.check(statistics.get("sampleEvidenceRef") in field.get("evidenceRefs", []), f"Field {asset.get('assetId')}.{field.get('path')} statistics cite evidence not carried by the field")
            statistics_evidence = evidence_by_id.get(statistics.get("sampleEvidenceRef"))
            field_id = f"{asset.get('assetId')}.{field.get('path')}"
            validation.check(
                statistics_evidence is not None
                and statistics_evidence.get("kind") == "field-profile"
                and statistics_evidence.get("outcome") == "passed"
                and statistics_evidence.get("maturity") in {"observed", "validated", "curated", "usage-proven"}
                and statistics_evidence.get("subject", {}).get("assetId") == asset.get("assetId")
                and statistics_evidence.get("sourceId") == profile.get("sourceId")
                and statistics_evidence.get("sourceVersion") == profile.get("sourceVersion")
                and statistics_evidence.get("authorizationScopeId") == profile.get("authorizationScopeId")
                and statistics_evidence.get("payload", {}).get("fields", {}).get(field.get("path")) is not None,
                f"Field {field_id} statistics evidence does not bind the field coordinate, projection scope, successful outcome, and field-profile kind",
            )
            outcomes = {row.get("family"): row.get("outcome") for row in statistics.get("families", []) if isinstance(row, dict)}
            if outcomes.get("missingness") == "passed":
                validation.check(statistics.get("nullRatio") is not None and statistics.get("count") is not None, f"Field {asset.get('assetId')}.{field.get('path')} passed missingness without results")
            if outcomes.get("cardinality") == "passed":
                validation.check(statistics.get("distinctCount") is not None, f"Field {asset.get('assetId')}.{field.get('path')} passed cardinality without a result")
            if outcomes.get("distribution") == "passed":
                validation.check(any(statistics.get(key) is not None for key in ("entropy", "mean", "quantiles", "concentration")), f"Field {asset.get('assetId')}.{field.get('path')} passed distribution without a result")
            if outcomes.get("format") == "passed":
                validation.check(bool(statistics.get("formatShares")) or statistics.get("minimumLength") is not None, f"Field {asset.get('assetId')}.{field.get('path')} passed format profiling without a result")
            if outcomes.get("temporal") == "passed":
                validation.check(statistics.get("minimumTime") is not None or statistics.get("cadenceSeconds") is not None, f"Field {asset.get('assetId')}.{field.get('path')} passed temporal profiling without a result")
            if outcomes.get("outlier") == "passed":
                validation.check(statistics.get("outlierRatio") is not None, f"Field {asset.get('assetId')}.{field.get('path')} passed outlier profiling without a result")
            if outcomes.get("nesting") == "passed":
                validation.check(statistics.get("nestingMaximumDepth") is not None and statistics.get("variantCount") is not None, f"Field {asset.get('assetId')}.{field.get('path')} passed nesting without results")
            if not statistics.get("exact") and statistics.get("distinctCount") is not None:
                validation.check(statistics.get("distinctCountIsApproximate") is True, f"Field {asset.get('assetId')}.{field.get('path')} sampled distinct count is not labelled approximate")
    for relationship in relationships.values():
        validation.check(relationship.get("kind") in relationship_kinds, f"Relationship {relationship.get('relationshipId')} kind is not in the semantic taxonomy")

    business = profile.get("businessModel", {})
    concept_groups = ("domains", "entities", "events", "states", "processes", "measures", "dimensions", "metrics", "scenarios", "glossary")
    concepts = [row for group in concept_groups for row in business.get(group, []) if isinstance(row, dict)]
    concept_ids = [row.get("conceptId") for row in concepts]
    validation.check(len(concept_ids) == len(set(concept_ids)), "Business model contains duplicate concept IDs")
    concept_set = set(concept_ids)
    entity_ids = {row.get("conceptId") for row in business.get("entities", [])}
    event_ids = {row.get("conceptId") for row in business.get("events", [])}
    process_ids = {row.get("conceptId") for row in business.get("processes", [])}
    field_paths = {
        f"{asset_id}.{field.get('path')}"
        for asset_id, asset in assets.items()
        for field in asset.get("fields", [])
        if field.get("path")
    }
    def validate_field_paths(owner: str, paths: list[Any]) -> None:
        for path in paths:
            validation.check(path in field_paths, f"{owner} references missing field path {path}")
    for group in ("entities", "events", "states", "processes", "measures", "dimensions", "metrics", "scenarios", "glossary"):
        validation.check(bool(business.get(group)), f"Business model exercises no {group} conformance vector")
    for row in business.get("events", []):
        validation.check(set(row.get("subjectEntityIds", [])) <= entity_ids, f"Event {row.get('conceptId')} references a missing or wrong-kind entity")
        for field in ("timestampPaths", "identityPaths", "actorPaths", "stateTransitionPaths"):
            validate_field_paths(f"Event {row.get('conceptId')} {field}", row.get(field, []))
    for row in business.get("entities", []):
        for field in ("currentStateAssetIds", "historyAssetIds"):
            validation.check(set(row.get(field, [])) <= set(assets), f"Entity {row.get('conceptId')} {field} references missing assets")
        for field in ("identityEvidenceRefs", "alternateIdentityEvidenceRefs", "counterEvidenceRefs"):
            validation.check(set(row.get(field, [])) <= set(evidence_by_id), f"Entity {row.get('conceptId')} {field} references missing evidence")
    for row in business.get("processes", []):
        validation.check(set(row.get("startEventIds", [])) <= event_ids, f"Process {row.get('conceptId')} startEventIds contain missing or wrong-kind events")
        validation.check(set(row.get("terminalEventIds", [])) <= event_ids, f"Process {row.get('conceptId')} terminalEventIds contain missing or wrong-kind events")
        validation.check(set(row.get("participantConceptIds", [])) <= (entity_ids | process_ids), f"Process {row.get('conceptId')} participants contain missing or wrong-kind concepts")
        validation.check(set(row.get("transitionEvidenceRefs", [])) <= set(evidence_by_id), f"Process {row.get('conceptId')} transition evidence references missing evidence")
    measure_ids = {row.get("conceptId") for row in business.get("measures", [])}
    dimension_ids = {row.get("conceptId") for row in business.get("dimensions", [])}
    metric_ids = {row.get("conceptId") for row in business.get("metrics", [])}
    for row in business.get("processes", []):
        validation.check(set(row.get("durationMeasureIds", [])) <= measure_ids, f"Process {row.get('conceptId')} duration measures contain missing or wrong-kind measures")
    for row in business.get("states", []):
        validate_field_paths(f"State {row.get('conceptId')}", row.get("valuePaths", []))
    for row in business.get("measures", []):
        validate_field_paths(f"Measure {row.get('conceptId')}", row.get("sourcePaths", []))
    for row in business.get("dimensions", []):
        validate_field_paths(f"Dimension {row.get('conceptId')}", row.get("sourcePaths", []))
    for row in business.get("metrics", []):
        validation.check(set(row.get("requiredAssetIds", [])) <= set(assets), f"Metric {row.get('conceptId')} references missing assets")
        validation.check(set(row.get("requiredRelationshipIds", [])) <= set(relationships), f"Metric {row.get('conceptId')} references missing relationships")
    for row in business.get("scenarios", []):
        validation.check(set(row.get("requiredConceptIds", [])) <= concept_set, f"Scenario {row.get('conceptId')} references missing concepts")
        validation.check(set(row.get("requiredMeasureIds", [])) <= measure_ids, f"Scenario {row.get('conceptId')} references missing measures")
        validation.check(set(row.get("requiredDimensionIds", [])) <= dimension_ids, f"Scenario {row.get('conceptId')} references missing dimensions")
        validation.check(set(row.get("candidateMetricIds", [])) <= metric_ids, f"Scenario {row.get('conceptId')} references missing metrics")
        validation.check(set(row.get("requiredAssetIds", [])) <= set(assets), f"Scenario {row.get('conceptId')} references missing assets")
        validation.check(set(row.get("requiredRelationshipIds", [])) <= set(relationships), f"Scenario {row.get('conceptId')} references missing relationships")
    for row in business.get("glossary", []):
        validation.check(set(row.get("mappedConceptIds", [])) <= concept_set, f"Glossary {row.get('conceptId')} references missing concepts")
        validation.check(set(row.get("mappedMetricIds", [])) <= metric_ids, f"Glossary {row.get('conceptId')} references missing metrics")
        validation.check(set(row.get("sourceRefs", [])) <= set(assets), f"Glossary {row.get('conceptId')} references missing source assets")
        validate_field_paths(f"Glossary {row.get('conceptId')}", row.get("mappedFieldPaths", []))
    validation.check(bool(profile.get("modelPatterns")), "Profile manifest exercises no model pattern conformance vector")
    pattern_ids = [pattern.get("patternId") for pattern in profile.get("modelPatterns", [])]
    validation.check(len(pattern_ids) == len(set(pattern_ids)), "Profile model patterns contain duplicate pattern IDs")
    pattern_kinds = [pattern.get("kind") for pattern in profile.get("modelPatterns", [])]
    validation.check(set(pattern_kinds) == {"storage", "hierarchy", "graph", "dimensional", "temporal"}, "Profile model pattern kinds do not cover the complete taxonomy")
    validation.check(len(pattern_kinds) == len(set(pattern_kinds)), "Profile model pattern kinds contain duplicates")
    for pattern in profile.get("modelPatterns", []):
        validation.check(set(pattern.get("assetIds", [])) <= set(assets), f"Model pattern {pattern.get('patternId')} references missing assets")
        for evidence_id in pattern.get("evidenceRefs", []):
            validation.check(evidence_id in evidence_by_id, f"Model pattern {pattern.get('patternId')} references missing evidence {evidence_id}")
        details = pattern.get("details", {})
        for field in ("identityPaths", "versionPaths", "levelPaths", "timePaths"):
            validate_field_paths(f"Model pattern {pattern.get('patternId')} {field}", details.get(field, []))
        for field in ("nodeAssetIds", "factAssetIds", "dimensionAssetIds", "eventAssetIds", "entityAssetIds"):
            validation.check(set(details.get(field, [])) <= set(assets), f"Model pattern {pattern.get('patternId')} {field} references missing assets")
        for field in ("parentRelationshipIds", "edgeRelationshipIds", "relationshipIds"):
            validation.check(set(details.get(field, [])) <= set(relationships), f"Model pattern {pattern.get('patternId')} {field} references missing relationships")

    for index in profile.get("indexes", []):
        validation.check(index.get("sourceId") == profile.get("sourceId"), "Index sourceId differs from profile manifest")
        validation.check(index.get("sourceVersion") == profile.get("sourceVersion"), "Index sourceVersion differs from profile manifest")
        validation.check(index.get("projectionId") == profile.get("projectionId"), "Index projectionId differs from profile manifest")
        validation.check(index.get("methodSetHash") == profile.get("methodSetHash"), "Index methodSetHash differs from profile manifest")
        validation.check(index.get("evidenceCutoff") == profile.get("evidenceCutoff"), "Index evidenceCutoff differs from profile manifest")
        validation.check(index.get("revocationEpoch") == profile.get("revocationEpoch"), "Index revocationEpoch differs from profile manifest")
        validation.check(index.get("policyHash") == profile.get("policyHash"), "Index policyHash differs from profile manifest")
        validation.check(index.get("authorizationScopeId") == profile.get("authorizationScopeId"), "Index authorization scope differs from profile manifest")

    for key in ("sourceId", "sourceVersion", "manifestVersion", "projectionId", "connectorId", "connectorVersion", "connectorCapabilityHash", "revocationEpoch", "policyHash", "authorizationScopeId", "taxonomyVersion", "pipelineVersion", "methodSetHash", "evidenceCutoff"):
        validation.check(
            capability.get(key) == profile.get(key),
            f"Capability manifest {key} differs from the profile projection coordinate",
        )
    validation.check(
        capability.get("profileManifestId") == profile.get("manifestId"),
        "Capability manifest does not reference its profile manifest",
    )

    receipt = load_json("examples/read-plan-validation-receipt.json", validation)
    if isinstance(receipt, dict):
        for key in ("sourceId", "sourceVersion", "manifestVersion", "connectorId", "connectorVersion", "connectorCapabilityHash", "policyHash", "authorizationScopeId", "evidenceCutoff"):
            validation.check(
                receipt.get(key) == profile.get(key),
                f"Validation receipt {key} differs from the manifest projection coordinate",
            )


def validate_policy_and_requirement_semantics(validation: Validation) -> None:
    try:
        import yaml  # type: ignore[import-not-found]
        policy = yaml.safe_load((ROOT / "config" / "reference-policy.yaml").read_text(encoding="utf-8"))
        hard_gate_list = policy["ranking"]["hardGates"]
        hard_gates = set(hard_gate_list)
        required_hard_gates = {"authorized", "policy-compatible", "current-version", "validation-status-compatible"}
        validation.check(required_hard_gates <= hard_gates, f"Ranking hard gates omit mandatory controls: {sorted(required_hard_gates - hard_gates)}")
        validation.check(policy["ranking"].get("authorizationPhase") == "before-candidate-generation", "Authorization is not declared before candidate generation")
        validation.check(hard_gate_list == ["authorized", "policy-compatible", "current-version", "validation-status-compatible"], "Ranking hard-gate order differs from the mandatory authorization-first sequence")
        weights = policy["ranking"]["weights"]
        validation.check(abs(sum(float(value) for value in weights.values()) - 1.0) < 1e-9, "Ranking weights must sum to 1.0")
        validation.check("costPenalty" in weights and "estimatedCost" not in weights, "Ranking cost must be represented as a penalty")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to validate reference policy semantics: {exc}")

    catalog = load_json("requirements/catalog.json", validation)
    if isinstance(catalog, dict):
        ids = {item.get("id") for item in catalog.get("requirements", []) if isinstance(item, dict)}
        expected = {f"FR-{number:03d}" for number in range(1, 37)} | {f"NFR-{number:03d}" for number in range(1, 8)}
        validation.check(ids == expected, f"Requirement ID set differs from the expected catalog: missing={sorted(expected - ids)}, extra={sorted(ids - expected)}")

    manifest_path = ROOT / "package.yaml"
    try:
        import yaml  # type: ignore[import-not-found]
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        declared = list(manifest.get("artifacts", []))
        validation.check(len(declared) == len(set(declared)), "package.yaml declares duplicate artifacts")
        validation.check(
            set(declared) == set(EXPECTED_ARTIFACTS),
            "package.yaml artifacts differ from the validator inventory: "
            f"missing={sorted(set(EXPECTED_ARTIFACTS) - set(declared))}, extra={sorted(set(declared) - set(EXPECTED_ARTIFACTS))}",
        )
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Unable to reconcile package.yaml artifacts: {exc}")

    try:
        import importlib.util

        scorer_path = ROOT / "scripts" / "evaluate_benchmark.py"
        specification = importlib.util.spec_from_file_location("profiler_benchmark_scorer", scorer_path)
        validation.check(specification is not None and specification.loader is not None, "Benchmark scorer cannot be loaded")
        if specification is not None and specification.loader is not None:
            scorer = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(scorer)
            corpus = load_json("benchmark/corpus.json", validation)
            comparison = load_json("benchmark/comparison.json", validation)
            corpus_schema = load_json("contracts/benchmark-corpus.schema.json", validation)
            comparison_schema = load_json("contracts/benchmark-comparison.schema.json", validation)
            if all(isinstance(value, dict) for value in (corpus, comparison, corpus_schema, comparison_schema)):
                schema_errors: list[str] = []
                validate_schema(
                    corpus,
                    corpus_schema,
                    corpus_schema,
                    "$",
                    schema_errors,
                    ROOT / "contracts" / "benchmark-corpus.schema.json",
                )
                validate_schema(
                    comparison,
                    comparison_schema,
                    comparison_schema,
                    "$",
                    schema_errors,
                    ROOT / "contracts" / "benchmark-comparison.schema.json",
                )
                validation.check(not schema_errors, f"Benchmark artifacts violate their contracts: {'; '.join(schema_errors)}")
                scorer_errors = scorer.score(corpus, comparison)
                validation.check(not scorer_errors, f"Benchmark comparison failed: {'; '.join(scorer_errors)}")
    except Exception as exc:  # noqa: BLE001
        validation.check(False, f"Benchmark governance validation failed: {exc}")


def validate_sanitization_and_placeholders(validation: Validation) -> None:
    text_files = [
        path for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in {".md", ".json", ".yaml", ".yml", ".feature", ".py"}
    ]
    for path in sorted(text_files):
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(ROOT).as_posix()
        if relative != "scripts/validate_package.py":
            for pattern in FORBIDDEN_PATTERNS:
                validation.check(re.search(pattern, text, re.IGNORECASE) is None, f"Forbidden identifying term in {relative}: /{pattern}/")
            for pattern in PLACEHOLDER_PATTERNS:
                validation.check(re.search(pattern, text, re.IGNORECASE) is None, f"Placeholder marker in {relative}: /{pattern}/")
        for match in EMAIL_ADDRESS_PATTERN.finditer(text):
            validation.check(
                is_approved_document_domain(match.group(1)),
                f"Non-example email domain in {relative}",
            )
        for match in ABSOLUTE_DOMAIN_PATTERN.finditer(text):
            validation.check(
                is_approved_document_domain(match.group(1)),
                f"Non-approved absolute domain in {relative}",
            )
        for pattern in USER_PROFILE_PATH_PATTERNS:
            validation.check(pattern.search(text) is None, f"User-profile path in {relative}")
        validation.check(
            DEPLOYED_RESOURCE_PATH_PATTERN.search(text) is None,
            f"Deployed-resource identifier path in {relative}",
        )


def validate_yaml_shape(validation: Validation) -> None:
    # Standard-library-only sanity checks: YAML files must have content, balanced
    # square/curly brackets per line, and no tab indentation. JSON examples and
    # contracts receive full parsing/schema validation above.
    for path in sorted(list(ROOT.rglob("*.yaml")) + list(ROOT.rglob("*.yml"))):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        validation.check("\t" not in text, f"Tab indentation in YAML: {relative}")
        validation.check(bool(re.search(r"^[A-Za-z0-9_-]+:", text, re.MULTILINE)), f"No YAML mapping keys found: {relative}")
        for number, line in enumerate(text.splitlines(), start=1):
            content = "" if line.lstrip().startswith("#") else line
            validation.check(content.count("[") == content.count("]"), f"Unbalanced [] in {relative}:{number}")
            validation.check(content.count("{") == content.count("}"), f"Unbalanced {{}} in {relative}:{number}")

    # Use a standards-compliant parser when it is already available, while keeping
    # the package runnable with the standard library alone.
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ValueError(f"duplicate mapping key {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )

    for path in sorted(list(ROOT.rglob("*.yaml")) + list(ROOT.rglob("*.yml"))):
        relative = path.relative_to(ROOT).as_posix()
        try:
            parsed = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
            validation.check(parsed is not None, f"YAML parsed to null: {relative}")
        except Exception as exc:  # noqa: BLE001 - validator aggregates failures
            validation.check(False, f"YAML parse failed for {relative}: {exc}")


# Floor for the total executed check count so a silently disabled gate shows up as a regression.
MINIMUM_CHECKS = 5600

GATES = [
    "validate_artifacts",    "validate_json_and_examples",
    "validate_standards",
    "validate_openapi_references",
    "validate_protected_resource_errors",
    "validate_openapi_stage_enum",
    "validate_agent_response_bounds",
    "validate_features_and_traceability",
    "validate_prompt_contracts",
    "validate_prompt_outputs",
    "validate_pipeline_registries",
    "validate_index_registry",
    "validate_maturity_rank",
    "validate_source_kind_registry",
    "validate_run_accounting",
    "validate_execution_receipts",
    "validate_projection_privacy",
    "validate_audit_chain",
    "validate_trusted_receipts",
    "validate_projection_seal",
    "validate_read_plan_bindings",
    "validate_api_receipts",
    "validate_retrieval_bundle",
    "validate_lifecycle_inventory",
    "validate_evidence_integrity",
    "validate_capability_negotiation",
    "validate_security_fixtures",
    "validate_example_references",
    "validate_policy_and_requirement_semantics",
    "validate_links",
    "validate_yaml_shape",
    "validate_sanitization_and_placeholders",
]


def run_declared_gates(validation: Validation, gate_names: list[str] | None = None) -> None:
    """Dispatch every declared gate and retain a runtime execution receipt."""
    names = list(GATES if gate_names is None else gate_names)
    validation.check(len(names) == len(set(names)), "Declared gate registry contains duplicate names")
    minimums: dict[str, int] = {}
    if gate_names is None:
        try:
            registry = load_verified_control(
                ROOT,
                issuer_registry_path=TRUST_REGISTRY_PATH,
                expected_registry_sha256=TRUST_REGISTRY_SHA256,
                expected_control_sha256=VALIDATION_CONTROL_SHA256,
                require_external=REQUIRE_EXTERNAL_TRUST,
            )
            validation.check(True, "Expected-gate manifest signature verified")
        except Exception as exc:  # noqa: BLE001
            registry = {}
            validation.check(False, f"Expected-gate manifest verification failed: {exc}")
        expected_names = registry.get("gates", []) if isinstance(registry, dict) else []
        minimums = registry.get("gateMinimumChecks", {}) if isinstance(registry, dict) else {}
        validation.check(names == expected_names, "Runtime gate registry differs from the independent expected-gate manifest")
        validation.check(set(minimums) == set(expected_names), "Expected-gate minimum check inventory differs from the gate registry")
        catalog = load_json("requirements/catalog.json", validation)
        if isinstance(catalog, dict):
            validation.check(registry.get("semanticBindingHash") == catalog.get("semanticBindingHash"), "Signed control semantic binding hash differs from the requirement catalog")
    scenarios_by_feature: dict[str, set[str]] = {}

    for ordinal, name in enumerate(names, start=1):
        gate = globals().get(name)
        before_checks = validation.checks
        before_errors = len(validation.errors)
        raised: str | None = None
        result: Any = None
        if not callable(gate):
            raised = "gate is not callable"
        else:
            try:
                if name == "validate_source_kind_registry":
                    result = gate(validation, scenarios_by_feature)
                else:
                    result = gate(validation)
            except Exception as exc:  # noqa: BLE001 - a gate exception is a failed receipt, not a process escape
                raised = f"{type(exc).__name__}: {exc}"

        checks_executed = validation.checks - before_checks
        failures_added = len(validation.errors) - before_errors
        validation.gate_executions.append(
            {
                "ordinal": ordinal,
                "name": name,
                "checksExecuted": checks_executed,
                "failuresAdded": failures_added,
                "raised": raised,
            }
        )
        if raised is not None:
            validation.check(False, f"Declared gate {name} failed to execute: {raised}")
        validation.check(checks_executed > 0, f"Declared gate {name} executed zero checks")
        if gate_names is None:
            validation.check(checks_executed >= int(minimums.get(name, 0)), f"Declared gate {name} executed {checks_executed} checks; expected at least {minimums.get(name, 0)}")
        if name == "validate_features_and_traceability" and isinstance(result, dict):
            scenarios_by_feature = result

    validation.check(
        [receipt["name"] for receipt in validation.gate_executions] == names,
        "Runtime gate receipt does not match the declared gate order",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the profiler package")
    parser.add_argument("--trust-mode", choices=("conformance", "production"), default="conformance")
    parser.add_argument("--trust-registry", type=Path)
    parser.add_argument("--trust-registry-sha256")
    parser.add_argument("--validation-control-sha256")
    parser.add_argument("--validation-verifier-sha256")
    args = parser.parse_args(argv)
    global TRUST_REGISTRY_PATH, TRUST_REGISTRY_SHA256, VALIDATION_CONTROL_SHA256, VALIDATION_VERIFIER_SHA256, REQUIRE_EXTERNAL_TRUST
    TRUST_REGISTRY_PATH = args.trust_registry
    TRUST_REGISTRY_SHA256 = args.trust_registry_sha256
    VALIDATION_CONTROL_SHA256 = args.validation_control_sha256
    VALIDATION_VERIFIER_SHA256 = args.validation_verifier_sha256
    REQUIRE_EXTERNAL_TRUST = args.trust_mode == "production"
    if REQUIRE_EXTERNAL_TRUST and (
        TRUST_REGISTRY_PATH is None
        or TRUST_REGISTRY_SHA256 is None
        or VALIDATION_CONTROL_SHA256 is None
        or VALIDATION_VERIFIER_SHA256 is None
    ):
        print(
            "FAIL: production trust mode requires --trust-registry, "
            "--trust-registry-sha256, --validation-control-sha256, "
            "and --validation-verifier-sha256"
        )
        return 1

    try:
        load_validation_verifier(VALIDATION_VERIFIER_SHA256, REQUIRE_EXTERNAL_TRUST)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: validation-verifier bootstrap verification failed: {exc}")
        return 1

    validation = Validation()
    run_declared_gates(validation)
    validation.check(
        validation.checks >= MINIMUM_CHECKS,
        f"Check count regressed to {validation.checks}; expected at least {MINIMUM_CHECKS}",
    )

    if validation.checks == 0:
        print("FAIL: validator executed zero checks")
        return 1

    if validation.errors:
        print(f"FAIL: {len(validation.errors)} failure(s) across {validation.checks} checks")
        for error in validation.errors:
            print(f"- {error}")
        return 1

    trust_label = "PRODUCTION" if REQUIRE_EXTERNAL_TRUST else "CONFORMANCE"
    print(
        f"PASS {trust_label}: {validation.checks} checks; {len(validation.gate_executions)} gates; "
        f"{len(EXPECTED_ARTIFACTS)} required artifacts; package is complete and sanitized"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())