#!/usr/bin/env python3
"""Verification for the signed validation control manifest."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _verify_file_pins(root: Path, control: dict[str, Any], field: str, label: str) -> list[dict[str, str]]:
    rows = control.get(field)
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"validation-control {field} must bind at least one {label} file")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
            raise ValueError(f"validation-control {label} file pin is malformed")
        relative = row.get("path")
        expected = row.get("sha256")
        if not isinstance(relative, str) or not relative or relative in seen:
            raise ValueError(f"validation-control {label} file paths must be unique")
        if not isinstance(expected, str) or len(expected) != 64:
            raise ValueError(f"validation-control {label} file hash is invalid")
        path = (root / relative).resolve()
        if root.resolve() not in path.parents or not path.is_file():
            raise ValueError(f"validation-control {label} file does not resolve inside the package: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected.lower():
            raise ValueError(f"validation-control {label} file hash mismatch: {relative}")
        seen.add(relative)
        normalized.append({"path": relative, "sha256": actual})
    if [row["path"] for row in normalized] != sorted(seen):
        raise ValueError(f"validation-control {label} files are not in canonical path order")
    return normalized


def load_trusted_issuers(
    root: Path,
    issuer_registry_path: Path | None = None,
    expected_registry_sha256: str | None = None,
    require_external: bool = False,
) -> dict[str, Any]:
    package_registry = (root / "security" / "trusted-issuers.json").resolve()
    registry_path = (issuer_registry_path or package_registry).resolve()
    if require_external and (registry_path == root.resolve() or root.resolve() in registry_path.parents):
        raise ValueError("production trust registry must be outside the package")
    raw = registry_path.read_bytes()
    actual_hash = hashlib.sha256(raw).hexdigest()
    if expected_registry_sha256 is not None and actual_hash != expected_registry_sha256.lower():
        raise ValueError("trusted issuer registry hash does not match the external pin")
    if require_external and expected_registry_sha256 is None:
        raise ValueError("production trust registry requires an external SHA-256 pin")
    registry = json.loads(raw)
    expected_use = "production" if require_external else "conformance-only"
    if registry.get("registryUse") != expected_use:
        raise ValueError(f"trusted issuer registry must declare {expected_use} use")
    issuers = registry.get("issuers")
    if not isinstance(issuers, list) or not issuers:
        raise ValueError("trusted issuer registry has no issuers")
    key_ids = [row.get("issuerKeyId") for row in issuers if isinstance(row, dict)]
    if len(key_ids) != len(issuers) or len(key_ids) != len(set(key_ids)) or any(not key_id for key_id in key_ids):
        raise ValueError("trusted issuer registry contains duplicate or missing key IDs")
    if require_external:
        if any(len(row.get("purposes", [])) != 1 for row in issuers):
            raise ValueError("production issuers must each be scoped to exactly one purpose")
        public_keys = [row.get("publicKeyBase64") for row in issuers]
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("production issuer keys must not be reused across purposes")
    return registry


def load_verified_control(
    root: Path,
    issuer_registry_path: Path | None = None,
    expected_registry_sha256: str | None = None,
    expected_control_sha256: str | None = None,
    require_external: bool = False,
) -> dict[str, Any]:
    control_path = root / "config" / "validation-gates.json"
    control_raw = control_path.read_bytes()
    actual_control_sha256 = hashlib.sha256(control_raw).hexdigest()
    if require_external and expected_control_sha256 is None:
        raise ValueError("production trust requires an independent validation-control SHA-256 pin")
    if expected_control_sha256 is not None and actual_control_sha256 != expected_control_sha256.lower():
        raise ValueError("validation-control SHA-256 does not match the independent pin")
    control = json.loads(control_raw)
    issuers = load_trusted_issuers(
        root,
        issuer_registry_path=issuer_registry_path,
        expected_registry_sha256=expected_registry_sha256,
        require_external=require_external,
    )
    body = {key: value for key, value in control.items() if key not in {"registryHash", "signature"}}
    expected_hash = hashlib.sha256(rfc8785.dumps(body)).hexdigest()
    if control.get("hashAlgorithm") != "sha256-jcs" or control.get("registryHash") != expected_hash:
        raise ValueError("validation-control hash mismatch")
    if control.get("signatureAlgorithm") != "ed25519":
        raise ValueError("validation-control signature algorithm is unsupported")
    issuer = next(
        (row for row in issuers.get("issuers", []) if row.get("issuerKeyId") == control.get("issuerKeyId")),
        None,
    )
    if issuer is None or "validation-control" not in issuer.get("purposes", []):
        raise ValueError("validation-control issuer is not authorized")
    sealed_at = datetime.fromisoformat(control["sealedAt"].replace("Z", "+00:00"))
    valid_from = datetime.fromisoformat(issuer["validFrom"].replace("Z", "+00:00"))
    valid_until = datetime.fromisoformat(issuer["validUntil"].replace("Z", "+00:00"))
    if not valid_from <= sealed_at < valid_until:
        raise ValueError("validation-control was sealed outside issuer validity")
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(issuer["publicKeyBase64"], validate=True)
    )
    try:
        public_key.verify(
            base64.b64decode(control["signature"], validate=True),
            bytes.fromhex(control["registryHash"]),
        )
    except InvalidSignature as exc:
        raise ValueError("validation-control signature is invalid") from exc

    if control.get("registryVersion") != "1.0.0":
        raise ValueError("validation-control registry version is unsupported")
    minimum_test_count = control.get("minimumTestCount")
    if type(minimum_test_count) is not int or minimum_test_count <= 0:
        raise ValueError("validation-control minimum test count must be positive")
    test_files = _verify_file_pins(root, control, "testFiles", "test")
    expected_suite_hash = hashlib.sha256(
        "".join(f"{row['path']}\0{row['sha256']}\n" for row in test_files).encode("utf-8")
    ).hexdigest()
    if control.get("testSuiteSha256") != expected_suite_hash:
        raise ValueError("validation-control test suite hash does not match its canonical file pins")
    _verify_file_pins(root, control, "promptFiles", "prompt")

    def require_unique_strings(field: str) -> list[str]:
        values = control.get(field)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) or not value for value in values)
            or len(values) != len(set(values))
        ):
            raise ValueError(f"validation-control {field} must contain unique non-empty strings")
        return values

    gates = require_unique_strings("gates")
    require_unique_strings("protectedOperationIds")
    minimums = control.get("gateMinimumChecks")
    if not isinstance(minimums, dict) or set(minimums) != set(gates):
        raise ValueError("validation-control gate minimum inventory differs from its gates")
    if any(type(value) is not int or value <= 0 for value in minimums.values()):
        raise ValueError("validation-control gate minimums must be positive integers")
    semantic_binding_hash = control.get("semanticBindingHash")
    if not isinstance(semantic_binding_hash, str) or len(semantic_binding_hash) != 64:
        raise ValueError("validation-control semantic binding hash is invalid")
    for field in ("benchmarkCorpusSha256", "benchmarkComparisonSha256", "benchmarkScorerSha256"):
        value = control.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(f"validation-control {field} is invalid")
    benchmark_paths = {
        "benchmarkCorpusSha256": root / "benchmark" / "corpus.json",
        "benchmarkComparisonSha256": root / "benchmark" / "comparison.json",
        "benchmarkScorerSha256": root / "scripts" / "evaluate_benchmark.py",
    }
    for field, path in benchmark_paths.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != control[field]:
            raise ValueError(f"validation-control {field} does not match package bytes")
    return control
