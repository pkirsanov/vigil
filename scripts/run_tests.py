#!/usr/bin/env python3
"""Fail-closed test runner for the package validator suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import importlib.util
import os
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

SCRIPT_DIR = Path(__file__).resolve().parent
CONTROL_PATH = SCRIPT_DIR / "validation_control.py"
ROOT = Path(__file__).resolve().parents[1]


def load_validation_verifier(expected_sha256: str | None, require_external: bool):
    """Hash the verifier with stdlib code before executing any verifier bytes."""
    if require_external and expected_sha256 is None:
        raise ValueError("production trust requires an external validation-verifier SHA-256 pin")
    actual_sha256 = hashlib.sha256(CONTROL_PATH.read_bytes()).hexdigest()
    if expected_sha256 is not None and actual_sha256 != expected_sha256.lower():
        raise ValueError("validation verifier SHA-256 does not match the external pin")
    spec = importlib.util.spec_from_file_location(
        "agent_data_profiler_test_validation_control", CONTROL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load package-local validation control from {CONTROL_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run profiler package tests")
    parser.add_argument("--trust-mode", choices=("conformance", "production"), default="conformance")
    parser.add_argument("--trust-registry", type=Path)
    parser.add_argument("--trust-registry-sha256")
    parser.add_argument("--validation-control-sha256")
    parser.add_argument("--validation-verifier-sha256")
    args = parser.parse_args(argv)
    require_external = args.trust_mode == "production"
    if require_external and (
        args.trust_registry is None
        or args.trust_registry_sha256 is None
        or args.validation_control_sha256 is None
        or args.validation_verifier_sha256 is None
    ):
        print(
            "FAIL: production trust mode requires --trust-registry, "
            "--trust-registry-sha256, --validation-control-sha256, "
            "and --validation-verifier-sha256"
        )
        return 1
    try:
        verifier = load_validation_verifier(args.validation_verifier_sha256, require_external)
        registry = verifier.load_verified_control(
            ROOT,
            issuer_registry_path=args.trust_registry,
            expected_registry_sha256=args.trust_registry_sha256,
            expected_control_sha256=args.validation_control_sha256,
            require_external=require_external,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: validation-control verification failed: {exc}")
        return 1
    minimum = int(registry["minimumTestCount"])
    suite = unittest.TestSuite()
    test_files = [(ROOT / row["path"]).resolve() for row in registry["testFiles"]]
    if not test_files:
        print("FAIL: discovered no test files")
        return 1
    for index, test_file in enumerate(test_files):
        spec = importlib.util.spec_from_file_location(f"package_test_{index}", test_file)
        if spec is None or spec.loader is None:
            print(f"FAIL: cannot load test module {test_file.relative_to(ROOT)}")
            return 1
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    discovered = suite.countTestCases()
    if discovered < minimum:
        print(f"FAIL: discovered {discovered} tests; expected at least {minimum}")
        return 1

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    executed = result.testsRun
    if executed != discovered:
        print(f"FAIL: executed {executed} of {discovered} discovered tests")
        return 1
    if result.skipped:
        print(f"FAIL: {len(result.skipped)} test(s) were skipped")
        return 1
    if result.expectedFailures or result.unexpectedSuccesses:
        print(
            f"FAIL: expectedFailures={len(result.expectedFailures)}, "
            f"unexpectedSuccesses={len(result.unexpectedSuccesses)}"
        )
        return 1
    if not result.wasSuccessful():
        return 1

    trust_label = "PRODUCTION" if require_external else "CONFORMANCE"
    print(f"PASS {trust_label}: {executed} tests executed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
