from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import importlib.util
import json
import math
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "package_validator",
    ROOT / "scripts" / "validate_package.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load package validator")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

BENCHMARK_SPEC = importlib.util.spec_from_file_location(
    "benchmark_scorer",
    ROOT / "scripts" / "evaluate_benchmark.py",
)
if BENCHMARK_SPEC is None or BENCHMARK_SPEC.loader is None:
    raise RuntimeError("Unable to load benchmark scorer")
BENCHMARK_SCORER = importlib.util.module_from_spec(BENCHMARK_SPEC)
BENCHMARK_SPEC.loader.exec_module(BENCHMARK_SCORER)


class PackageValidatorTests(unittest.TestCase):
    def load(self, relative_path: str):
        return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))

    def validate(self, instance, schema, schema_path: str | None = None):
        errors: list[str] = []
        full_path = ROOT / schema_path if schema_path is not None else None
        VALIDATOR.validate_schema(instance, schema, schema, "$", errors, full_path)
        return errors

    def reseal_validation_control(self, document, private_key, issuer_key_id):
        import rfc8785

        document["issuerKeyId"] = issuer_key_id
        body = {
            key: value
            for key, value in document.items()
            if key not in {"registryHash", "signature"}
        }
        document["registryHash"] = hashlib.sha256(rfc8785.dumps(body)).hexdigest()
        document["signature"] = base64.b64encode(
            private_key.sign(bytes.fromhex(document["registryHash"]))
        ).decode()

    def bind_test_files(self, control, root: Path):
        test_files = []
        for path in sorted((root / "tests").glob("test_*.py")):
            test_files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
        control["testFiles"] = test_files
        control["testSuiteSha256"] = hashlib.sha256(
            "".join(f"{row['path']}\0{row['sha256']}\n" for row in test_files).encode("utf-8")
        ).hexdigest()

    def create_external_test_registry(self, directory: Path):
        private_key = Ed25519PrivateKey.generate()
        issuer_key_id = "ephemeral-validation-control"
        registry = {
            "registryVersion": "1.0.0",
            "registryUse": "production",
            "issuers": [
                {
                    "issuerKeyId": issuer_key_id,
                    "algorithm": "ed25519",
                    "publicKeyBase64": base64.b64encode(
                        private_key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw,
                        )
                    ).decode(),
                    "purposes": ["validation-control"],
                    "validFrom": "2026-01-01T00:00:00Z",
                    "validUntil": "2027-01-01T00:00:00Z",
                }
            ],
        }
        path = directory / "external-trusted-issuers.json"
        raw = (json.dumps(registry, indent=2) + "\n").encode()
        path.write_bytes(raw)
        return private_key, issuer_key_id, path, hashlib.sha256(raw).hexdigest()

    def validation_verifier_hash(self, root: Path = ROOT):
        return hashlib.sha256((root / "scripts" / "validation_control.py").read_bytes()).hexdigest()

    def test_source_example_matches_contract(self):
        source = self.load("examples/source-descriptor.json")
        schema = self.load("contracts/source-descriptor.schema.json")
        self.assertEqual([], self.validate(source, schema))

    def test_unknown_source_property_is_rejected(self):
        source = self.load("examples/source-descriptor.json")
        schema = self.load("contracts/source-descriptor.schema.json")
        mutated = copy.deepcopy(source)
        mutated["embeddedSecret"] = "redacted"
        errors = self.validate(mutated, schema)
        self.assertTrue(any("unexpected property embeddedSecret" in error for error in errors))

    def test_missing_manifest_version_is_rejected(self):
        manifest = self.load("examples/profile-manifest.json")
        schema = self.load("contracts/profile-manifest.schema.json")
        mutated = copy.deepcopy(manifest)
        del mutated["sourceVersion"]
        errors = self.validate(mutated, schema, "contracts/profile-manifest.schema.json")
        self.assertTrue(any("missing required property sourceVersion" in error for error in errors))

    def test_validated_evidence_cannot_have_not_run_outcome(self):
        evidence = self.load("examples/evidence-record.json")
        schema = self.load("contracts/evidence-record.schema.json")
        mutated = copy.deepcopy(evidence)
        mutated["maturity"] = "validated"
        mutated["outcome"] = "not-run"
        errors = self.validate(mutated, schema)
        self.assertTrue(any("is not in enum" in error for error in errors))

    def test_full_package_validation_executes_nonzero_checks(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_artifacts(validation)
        VALIDATOR.validate_json_and_examples(validation)
        VALIDATOR.validate_features_and_traceability(validation)
        self.assertGreater(validation.checks, 0)
        self.assertEqual([], validation.errors)

    def test_validator_import_resolves_shared_control_from_package_root(self):
        result = subprocess.run(
            [sys.executable, "-c", "import scripts.validate_package"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_standards_validation_accepts_registered_cross_schema_references(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_standards(validation)
        self.assertGreater(validation.checks, 0)
        self.assertEqual([], validation.errors)

    def test_prompt_contract_references_resolve(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_prompt_contracts(validation)
        self.assertGreater(validation.checks, 0)
        self.assertEqual([], validation.errors)

    def test_pipeline_registries_reconcile(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_pipeline_registries(validation)
        self.assertGreater(validation.checks, 0)
        self.assertEqual([], validation.errors)

    def run_against_mutated_package(self, mutations, checker):
        """Copy the package to a scratch directory, apply mutations, and run one checker."""
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            for relative_path, mutate in mutations.items():
                path = target / relative_path
                document = json.loads(path.read_text(encoding="utf-8"))
                mutate(document)
                path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                checker(validation)
                return validation
            finally:
                VALIDATOR.ROOT = original_root

    def test_evidence_integrity_detects_a_forged_payload_hash(self):
        def forge(document):
            document["records"][0]["payloadHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/evidence-bundle.json": forge},
            VALIDATOR.validate_evidence_integrity,
        )
        self.assertTrue(any("payloadHash mismatch" in error for error in validation.errors))

    def test_capability_negotiation_detects_privilege_escalation(self):
        def escalate(document):
            document["effectiveCapabilities"].append("resolve-reference")

        validation = self.run_against_mutated_package(
            {"examples/source-descriptor.json": escalate},
            VALIDATOR.validate_capability_negotiation,
        )
        self.assertTrue(any("intersection" in error for error in validation.errors))

    def test_run_accounting_detects_zero_work_completion(self):
        def zero_work(document):
            for stage in document["stages"]:
                if stage["stageId"] == "publish":
                    stage["itemsCompleted"] = 0
                    stage["itemsAttempted"] = 0
                    stage["itemsNotRun"] = stage["itemsExpected"]

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": zero_work},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("zero work" in error for error in validation.errors))

    def test_run_accounting_detects_unreconciled_counters(self):
        def unbalance(document):
            document["stages"][0]["itemsExpected"] = 5

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": unbalance},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("do not reconcile" in error for error in validation.errors))

    def test_source_kind_registry_detects_an_unaccounted_stage(self):
        def drop_stage(document):
            document["sourceKinds"][0]["conditionalStages"].pop()

        validation = self.run_against_mutated_package(
            {"pipeline/source-kind-profiles.json": drop_stage},
            lambda validation: VALIDATOR.validate_source_kind_registry(
                validation, VALIDATOR.parse_features(VALIDATOR.Validation())
            ),
        )
        self.assertTrue(any("does not account for every canonical stage" in error for error in validation.errors))

    def test_security_fixtures_detect_a_weakened_locator_contract(self):
        def weaken(document):
            locator = document["properties"]["locator"]["properties"]
            locator["resource"].pop("pattern")

        validation = self.run_against_mutated_package(
            {"contracts/source-registration-request.schema.json": weaken},
            VALIDATOR.validate_security_fixtures,
        )
        self.assertTrue(any("does not constrain locator resources" in error for error in validation.errors))

    def test_traceability_detects_a_missing_scenario(self):
        def rename(document):
            document["requirements"][0]["bdd"][0]["scenarioRef"] = "source-onboarding:this scenario does not exist"

        validation = self.run_against_mutated_package(
            {"requirements/catalog.json": rename},
            VALIDATOR.validate_features_and_traceability,
        )
        self.assertTrue(any("BDD scenario not found" in error for error in validation.errors))

    def test_traceability_detects_uncovered_acceptance_criteria(self):
        def strip(document):
            document["requirements"][0]["bdd"] = [
                mapping for mapping in document["requirements"][0]["bdd"]
                if mapping["acceptanceId"] != "AC-02"
            ]

        validation = self.run_against_mutated_package(
            {"requirements/catalog.json": strip},
            VALIDATOR.validate_features_and_traceability,
        )
        self.assertTrue(any("acceptance mapping differs" in error for error in validation.errors))

    def test_read_plan_bindings_detect_an_undeclared_parameter(self):
        def dangle(document):
            document["parameters"] = []

        validation = self.run_against_mutated_package(
            {"examples/read-plan.json": dangle},
            VALIDATOR.validate_read_plan_bindings,
        )
        self.assertTrue(any("undeclared parameter" in error for error in validation.errors))

    def test_read_plan_bindings_detect_a_forged_plan_hash(self):
        def forge(document):
            document["planHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/read-plan-validation-receipt.json": forge},
            VALIDATOR.validate_read_plan_bindings,
        )
        self.assertTrue(any("planHash mismatch" in error for error in validation.errors))

    def test_lifecycle_inventory_detects_an_omitted_store(self):
        def omit(document):
            document["stores"] = [
                store for store in document["stores"] if store["storeKind"] != "semantic-index"
            ]

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": omit},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("omits governed stores" in error for error in validation.errors))

    def test_prompt_outputs_detect_a_contract_violation(self):
        def corrupt(document):
            document["$defs"]["relationshipSemanticVerdict"]["properties"]["verdict"]["enum"] = ["only-this"]

        validation = self.run_against_mutated_package(
            {"contracts/prompt-contracts.schema.json": corrupt},
            VALIDATOR.validate_prompt_outputs,
        )
        self.assertTrue(any("violates its contract" in error for error in validation.errors))

    def test_evidence_integrity_detects_a_divergent_logical_key(self):
        def diverge(document):
            document["records"][0]["logicalKey"]["predicate"] = "unrelated-predicate"

        validation = self.run_against_mutated_package(
            {"examples/evidence-bundle.json": diverge},
            VALIDATOR.validate_evidence_integrity,
        )
        self.assertTrue(any("logicalKey predicate differs" in error for error in validation.errors))

    def test_execution_receipts_detect_usage_beyond_a_declared_limit(self):
        def exceed(document):
            document["usage"]["expandedBytes"] = document["limits"]["expandedBytes"] * 10

        validation = self.run_against_mutated_package(
            {"examples/parser-execution.json": exceed},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("exceeds its limit" in error for error in validation.errors))

    def test_execution_receipts_detect_an_unbound_cache_entry(self):
        def unbind(document):
            document["cache"]["admissionPolicyHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": unbind},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("not bound to the model-admission policy hash" in error for error in validation.errors))

    def test_example_references_detect_a_stale_index_projection(self):
        def stale(document):
            document["indexes"][0]["projectionId"] = "90000000-0000-4000-8000-000000000009"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": stale},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("Index projectionId differs" in error for error in validation.errors))

    def test_source_kind_registry_detects_an_unexecutable_required_stage(self):
        def strip_capability(document):
            for row in document["sourceKinds"]:
                if row["id"] == "custom":
                    row["requiredConnectorCapabilities"] = ["enumerate-assets"]

        validation = self.run_against_mutated_package(
            {"pipeline/source-kind-profiles.json": strip_capability},
            lambda validation: VALIDATOR.validate_source_kind_registry(
                validation, VALIDATOR.parse_features(VALIDATOR.Validation())
            ),
        )
        self.assertTrue(any("supported but lacks capabilities" in error for error in validation.errors))

    def test_pipeline_registries_detect_a_stage_table_contradiction(self):
        def flip(document):
            for row in document["stages"]:
                if row["id"] == "quality-freshness":
                    row["required"] = True

        validation = self.run_against_mutated_package(
            {"pipeline/stages.json": flip},
            VALIDATOR.validate_pipeline_registries,
        )
        self.assertTrue(any("pipeline/stages.json declares" in error for error in validation.errors))

    def run_against_mutated_text(self, relative_path, mutate, checker):
        """Copy the package to a scratch directory, apply a text mutation, and run one checker."""
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            path = target / relative_path
            path.write_text(mutate(path.read_text(encoding="utf-8")), encoding="utf-8")
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                checker(validation)
                return validation
            finally:
                VALIDATOR.ROOT = original_root

    def test_every_declared_gate_executes_through_runtime_dispatch(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.run_declared_gates(validation)
        self.assertEqual(VALIDATOR.GATES, [row["name"] for row in validation.gate_executions])
        self.assertTrue(all(row["checksExecuted"] > 0 for row in validation.gate_executions))
        self.assertTrue(all(row["raised"] is None for row in validation.gate_executions))
        self.assertEqual([], validation.errors)

    def test_runtime_dispatch_rejects_a_gate_that_executes_no_checks(self):
        gate_name = "validate_test_noop"
        setattr(VALIDATOR, gate_name, lambda validation: None)
        try:
            validation = VALIDATOR.Validation()
            VALIDATOR.run_declared_gates(validation, [gate_name])
        finally:
            delattr(VALIDATOR, gate_name)
        self.assertEqual(0, validation.gate_executions[0]["checksExecuted"])
        self.assertTrue(any("executed zero checks" in error for error in validation.errors))

    def test_sanitization_gate_detects_a_forbidden_term_and_placeholder(self):
        # Assembled at runtime so this file does not itself trip the sanitization gate.
        identity_marker = "private-source-" + "marker"
        marker = "TO" + "DO"

        def contaminate(text):
            return f"{text}\n\nThis contains {identity_marker} and is marked {marker}.\n"

        validation = self.run_against_mutated_text(
            "docs/00-executive-overview.md",
            contaminate,
            VALIDATOR.validate_sanitization_and_placeholders,
        )
        self.assertTrue(any("Forbidden identifying term" in error for error in validation.errors))
        self.assertTrue(any("Placeholder marker" in error for error in validation.errors))

    def test_sanitization_gate_detects_identity_locators(self):
        non_example_domain = "internal-identity." + "test"
        email = "sample-person@" + non_example_domain
        user_path = "C:" + "\\Users\\sample-person\\profile.txt"
        account_id = "12345678-1234-4234-8234-" + "123456789012"
        resource_path = f"/subscriptions/{account_id}/resourceGroups/sample"

        def contaminate(text):
            return f"{text}\n{email}\nhttps://{non_example_domain}/data\n{user_path}\n{resource_path}\n"

        for relative_path in (
            "docs/00-executive-overview.md",
            "scripts/validate_package.py",
        ):
            with self.subTest(relative_path=relative_path):
                validation = self.run_against_mutated_text(
                    relative_path,
                    contaminate,
                    VALIDATOR.validate_sanitization_and_placeholders,
                )
                self.assertTrue(any("Non-example email domain" in error for error in validation.errors))
                self.assertTrue(any("Non-approved absolute domain" in error for error in validation.errors))
                self.assertTrue(any("User-profile path" in error for error in validation.errors))
                self.assertTrue(any("Deployed-resource identifier path" in error for error in validation.errors))

    def test_link_gate_detects_a_broken_relative_link(self):
        def break_link(text):
            return text + "\n[missing](./does-not-exist.md)\n"

        validation = self.run_against_mutated_text(
            "docs/00-executive-overview.md",
            break_link,
            VALIDATOR.validate_links,
        )
        self.assertTrue(any("Broken relative link" in error for error in validation.errors))

    def test_yaml_gate_detects_tab_indentation(self):
        def add_tab(text):
            return text.replace("policyVersion: 1.0.0", "policyVersion: 1.0.0\nbroken:\n\tvalue: 1", 1)

        validation = self.run_against_mutated_text(
            "config/reference-policy.yaml",
            add_tab,
            VALIDATOR.validate_yaml_shape,
        )
        self.assertTrue(any("Tab indentation" in error for error in validation.errors))

    def test_policy_gate_detects_unbalanced_ranking_weights(self):
        def unbalance(text):
            return text.replace("costPenalty: 0.05", "costPenalty: 0.25", 1)

        validation = self.run_against_mutated_text(
            "config/reference-policy.yaml",
            unbalance,
            VALIDATOR.validate_policy_and_requirement_semantics,
        )
        self.assertTrue(any("Ranking weights must sum to 1.0" in error for error in validation.errors))

    def test_openapi_reference_gate_detects_a_missing_contract_file(self):
        def repoint(text):
            return text.replace("./read-plan.schema.json", "./this-contract-does-not-exist.schema.json")

        validation = self.run_against_mutated_text(
            "contracts/api.openapi.yaml",
            repoint,
            VALIDATOR.validate_openapi_references,
        )
        self.assertTrue(any("missing contract file" in error for error in validation.errors))

    def test_agent_response_bounds_detect_unbounded_free_text(self):
        def unbound(document):
            document["required"].remove("responsePolicy")

        validation = self.run_against_mutated_package(
            {"contracts/retrieval-bundle.schema.json": unbound},
            VALIDATOR.validate_agent_response_bounds,
        )
        self.assertTrue(any("RetrievalBundle does not require a response safety policy" in error for error in validation.errors))

    def test_agent_response_bounds_detect_a_union_typed_unbounded_string(self):
        def unbound(document):
            document["properties"]["responsePolicy"]["$ref"] = "projection-coordinate.schema.json"

        validation = self.run_against_mutated_package(
            {"contracts/retrieval-bundle.schema.json": unbound},
            VALIDATOR.validate_agent_response_bounds,
        )
        self.assertTrue(any("RetrievalBundle response safety policy is not contract-bound" in error for error in validation.errors))

    def test_agent_response_bounds_cover_the_execution_result(self):
        def unbound(document):
            document["required"].remove("responsePolicy")

        validation = self.run_against_mutated_package(
            {"contracts/read-execution-result.schema.json": unbound},
            VALIDATOR.validate_agent_response_bounds,
        )
        self.assertTrue(any("ReadExecutionResult does not require a response safety policy" in error for error in validation.errors))

    def test_index_registry_detects_metadata_from_another_kind(self):
        def borrow(document):
            for kind in document["indexKinds"]:
                if kind["id"] == "lexical":
                    kind["requiredMetadata"].extend(["modelRef", "dimensions"])

        validation = self.run_against_mutated_package(
            {"pipeline/index-registry.json": borrow},
            VALIDATOR.validate_index_registry,
        )
        self.assertTrue(any("does not require for it" in error for error in validation.errors))

    def test_maturity_rank_detects_a_response_enum_drift(self):
        def drift(document):
            document["properties"]["items"]["items"]["properties"]["maturity"]["enum"].remove("usage-proven")

        validation = self.run_against_mutated_package(
            {"contracts/retrieval-bundle.schema.json": drift},
            VALIDATOR.validate_maturity_rank,
        )
        self.assertTrue(any("response maturity differs" in error for error in validation.errors))

    def test_a_completed_parse_with_failed_cleanup_remains_expressible(self):
        receipt = self.load("examples/parser-execution.json")
        schema = self.load("contracts/parser-execution.schema.json")
        mutated = copy.deepcopy(receipt)
        mutated["cleanup"].update(
            completed=False,
            residualArtifactCount=2,
            cleanupFailureReasonCode="CLEANUP_TIMEOUT",
        )
        self.assertEqual([], self.validate(mutated, schema, "contracts/parser-execution.schema.json"))

    def test_audit_chain_gate_detects_a_tampered_event(self):
        def tamper(document):
            document["authorization"]["decision"] = "denied"

        validation = self.run_against_mutated_package(
            {"examples/audit-event.json": tamper},
            VALIDATOR.validate_audit_chain,
        )
        self.assertTrue(any("payloadSha256 mismatch" in error for error in validation.errors))

    def test_execution_receipts_detect_a_self_inflated_parser_limit(self):
        def inflate(document):
            document["limits"]["expandedBytes"] *= 1000
            document["usage"]["expandedBytes"] = document["limits"]["expandedBytes"] // 2

        validation = self.run_against_mutated_package(
            {"examples/parser-execution.json": inflate},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("exceeds the policy ceiling" in error for error in validation.errors))

    def test_security_fixtures_detect_a_relabelled_negative_case(self):
        def relabel(document):
            for case in document["cases"]:
                if case["caseId"] == "secret-in-display-name":
                    case["expectedReasonCode"] = "LOCATOR_ESCAPE"

        validation = self.run_against_mutated_package(
            {"security/registration-negative-cases.json": relabel},
            VALIDATOR.validate_security_fixtures,
        )
        self.assertTrue(any("disagrees with the secret-scan rule" in error for error in validation.errors))

    def test_evidence_integrity_detects_an_undeclared_cross_scope_relationship(self):
        def widen(document):
            for record in document["records"]:
                if record.get("kind") == "relationship-validation":
                    record["payload"]["right"]["authorizationScopeId"] = "another-tenant"

        validation = self.run_against_mutated_package(
            {"examples/evidence-bundle.json": widen},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("endpoint scopes derive" in error for error in validation.errors))

    def test_example_references_detect_a_foreign_scope_asset(self):
        def foreign(document):
            document["assets"][0]["authorizationScopeId"] = "another-tenant"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": foreign},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("authorization scope differs from profile manifest" in error for error in validation.errors))

    def test_example_references_detect_wrong_kind_validation_evidence(self):
        def repoint(document):
            document["relationships"][0]["validationEvidenceRef"] = "22222222-2222-4222-8222-222222222222"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": repoint},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("instead of relationship-validation" in error for error in validation.errors))

    def test_index_registry_detects_a_store_kind_drift(self):
        def drift(document):
            document["nonIndexGovernedStores"].remove("backup")

        validation = self.run_against_mutated_package(
            {"pipeline/index-registry.json": drift},
            VALIDATOR.validate_index_registry,
        )
        self.assertTrue(any("differ from the index registry" in error for error in validation.errors))

    def test_maturity_rank_detects_an_inverted_ordering(self):
        def invert(text):
            return text.replace("  inferred: 1\n  observed: 3", "  inferred: 3\n  observed: 1", 1)

        validation = self.run_against_mutated_text(
            "taxonomies/evidence-kinds.yaml",
            invert,
            VALIDATOR.validate_maturity_rank,
        )
        self.assertTrue(any("must outrank a generated hypothesis" in error for error in validation.errors))

    def test_source_kind_registry_detects_a_misclassified_stage(self):
        def misclassify(document):
            row = document["sourceKinds"][0]
            stage = row["conditionalStages"].pop()
            row["supportedStages"].append(stage)

        validation = self.run_against_mutated_package(
            {"pipeline/source-kind-profiles.json": misclassify},
            lambda validation: VALIDATOR.validate_source_kind_registry(
                validation, VALIDATOR.parse_features(VALIDATOR.Validation())
            ),
        )
        self.assertTrue(any("supported but" in error for error in validation.errors))

    def test_runtime_dispatch_rejects_a_gate_exception(self):
        gate_name = "validate_test_exception"

        def raise_error(validation):
            raise RuntimeError("seeded gate failure")

        setattr(VALIDATOR, gate_name, raise_error)
        try:
            validation = VALIDATOR.Validation()
            VALIDATOR.run_declared_gates(validation, [gate_name])
        finally:
            delattr(VALIDATOR, gate_name)
        self.assertIn("RuntimeError", validation.gate_executions[0]["raised"])
        self.assertTrue(any("failed to execute" in error for error in validation.errors))

    def test_runtime_dispatch_rejects_duplicate_gate_names(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.run_declared_gates(validation, ["validate_artifacts", "validate_artifacts"])
        self.assertTrue(any("duplicate names" in error for error in validation.errors))

    def test_secret_scanner_detects_unlabelled_entropy_and_preserves_benign_ids(self):
        self.assertTrue(VALIDATOR.detects_secret_like_input("c3VwZXItc2Vuc2l0aXZlLWNyZWRlbnRpYWwtOTg3NjU0MzIx"))
        self.assertTrue(VALIDATOR.detects_secret_like_input("credential_prod_D7sF9kQ2mV8xL4zN6pR1"))
        self.assertFalse(VALIDATOR.detects_secret_like_input("11111111-1111-4111-8111-111111111111"))
        self.assertFalse(VALIDATOR.detects_secret_like_input("datasets/orders/version-2026"))

    def test_run_accounting_detects_an_unresolvable_typed_receipt(self):
        def dangle(document):
            document["stages"][0]["receiptRefs"][0]["receiptId"] = "90000000-0000-4000-8000-999999999999"

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": dangle},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("references missing receipt" in error for error in validation.errors))

    def test_run_accounting_detects_a_wrong_receipt_type(self):
        def wrong_type(document):
            document["stages"][0]["receiptRefs"][0]["receiptType"] = "authorization-scope-and-policy-hash"

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": wrong_type},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("declares the wrong receipt type" in error for error in validation.errors))

    def test_run_accounting_detects_receipt_work_drift(self):
        def drift(document):
            document["receipts"][0]["work"]["completed"] = 0

        validation = self.run_against_mutated_package(
            {"examples/stage-receipt-bundle.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("work accounting differs" in error for error in validation.errors))

    def test_run_accounting_detects_receipt_registry_drift(self):
        def drift(document):
            document["$defs"]["receiptType"]["enum"].remove("atomic-current-pointer-and-publication-event")

        validation = self.run_against_mutated_package(
            {"contracts/stage-receipt-bundle.schema.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("receipt types differ" in error for error in validation.errors))

    def test_retrieval_gate_detects_an_undeclared_omission_section(self):
        def add_section(document):
            document["coverageReceipt"]["omittedBySection"]["hidden"] = 0

        validation = self.run_against_mutated_package(
            {"examples/retrieval-bundle.json": add_section},
            VALIDATOR.validate_retrieval_bundle,
        )
        self.assertTrue(any("undeclared or missing section" in error for error in validation.errors))

    def test_retrieval_gate_detects_unreconciled_candidates(self):
        def drift(document):
            document["coverageReceipt"]["authorizedCandidatesConsidered"] += 1

        validation = self.run_against_mutated_package(
            {"examples/retrieval-bundle.json": drift},
            VALIDATOR.validate_retrieval_bundle,
        )
        self.assertTrue(any("candidate accounting does not reconcile" in error for error in validation.errors))

    def test_retrieval_gate_detects_a_caveat_without_evidence(self):
        def strip(document):
            document["caveats"][0]["evidenceRefs"] = []

        validation = self.run_against_mutated_package(
            {"examples/retrieval-bundle.json": strip},
            VALIDATOR.validate_retrieval_bundle,
        )
        self.assertTrue(any("cites no evidence" in error for error in validation.errors))

    def test_retrieval_gate_detects_same_evidence_on_both_conflict_sides(self):
        def collapse(document):
            document["conflicts"][0]["counterEvidenceRefs"] = list(document["conflicts"][0]["supportingEvidenceRefs"])

        validation = self.run_against_mutated_package(
            {"examples/retrieval-bundle.json": collapse},
            VALIDATOR.validate_retrieval_bundle,
        )
        self.assertTrue(any("same evidence on both sides" in error for error in validation.errors))

    def test_protected_resource_gate_detects_a_distinguishable_forbidden_response(self):
        def expose(text):
            old = "'404': { $ref: '#/components/responses/ProtectedResourceUnavailable' }"
            new = "'403': { $ref: '#/components/responses/Forbidden' }"
            return text.replace(old, new, 1)

        validation = self.run_against_mutated_text(
            "contracts/api.openapi.yaml",
            expose,
            VALIDATOR.validate_protected_resource_errors,
        )
        self.assertTrue(any("distinguishable 403" in error for error in validation.errors))

    def test_protected_resource_gate_detects_runtime_composed_problem_detail(self):
        def widen(text):
            return text.replace(
                "enum: [null, Request rejected., Request conflicts with current state., Request limit exceeded.]",
                "type: [string, 'null']\n          maxLength: 500",
                1,
            )

        validation = self.run_against_mutated_text(
            "contracts/api.openapi.yaml",
            widen,
            VALIDATOR.validate_protected_resource_errors,
        )
        self.assertTrue(any("runtime-composed text" in error for error in validation.errors))

    def test_audit_chain_rejects_denied_success_narrative(self):
        def deny(document):
            document["authorization"]["decision"] = "denied"
            document["authorization"]["reasonCode"] = "POLICY_DENIED"

        validation = self.run_against_mutated_package(
            {"examples/audit-event.json": deny},
            VALIDATOR.validate_audit_chain,
        )
        self.assertTrue(any("reports a non-denied outcome" in error for error in validation.errors))

    def test_audit_chain_rejects_receipt_bound_to_wrong_action(self):
        def repoint(document):
            document["auditEventId"] = "40000000-0000-4000-8000-000000000001"

        validation = self.run_against_mutated_package(
            {"examples/cancellation-receipt.json": repoint},
            VALIDATOR.validate_audit_chain,
        )
        self.assertTrue(any("not bound to a run.cancel" in error for error in validation.errors))

    def test_trusted_receipts_require_a_nonempty_source_extension_vector(self):
        def remove(document):
            document["sourceExtensions"] = []

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": remove},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("no source-extension conformance vector" in error for error in validation.errors))

    def test_trusted_receipts_detect_a_tampered_extension_payload(self):
        def tamper(document):
            document["sourceExtensions"][0]["payload"]["metrics"][0]["value"] += 1

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": tamper},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("payloadHash mismatch" in error for error in validation.errors))

    def test_trusted_receipts_detect_a_missing_extension_evidence_reference(self):
        def dangle(document):
            document["sourceExtensions"][0]["evidenceRefs"] = ["92000000-0000-4000-8000-000000000001"]

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": dangle},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("cites missing evidence" in error for error in validation.errors))

    def test_runtime_dispatch_detects_removal_of_a_real_gate(self):
        removed = VALIDATOR.GATES.pop()
        try:
            validation = VALIDATOR.Validation()
            VALIDATOR.run_declared_gates(validation)
        finally:
            VALIDATOR.GATES.append(removed)
        self.assertTrue(any("independent expected-gate manifest" in error for error in validation.errors))

    def test_fail_closed_runner_rejects_zero_discovered_tests(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            target = scratch_path / "kit"
            shutil.copytree(ROOT, target)
            (target / "tests" / "test_validate_package.py").write_text("# deliberately empty\n", encoding="utf-8")
            private_key, issuer_key_id, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
            control_path = target / "config" / "validation-gates.json"
            control = json.loads(control_path.read_text(encoding="utf-8"))
            control["minimumTestCount"] = 1
            self.bind_test_files(control, target)
            self.reseal_validation_control(control, private_key, issuer_key_id)
            control_path.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            control_hash = hashlib.sha256(control_path.read_bytes()).hexdigest()
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/run_tests.py",
                    "--trust-mode",
                    "production",
                    "--trust-registry",
                    str(registry_path),
                    "--trust-registry-sha256",
                    registry_hash,
                    "--validation-control-sha256",
                    control_hash,
                    "--validation-verifier-sha256",
                    self.validation_verifier_hash(target),
                ],
                cwd=target,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("discovered 0 tests", result.stdout)

    def test_policy_gate_detects_removed_authorization_hard_gate(self):
        def remove(text):
            return text.replace("    - authorized\n", "", 1)

        validation = self.run_against_mutated_text(
            "config/reference-policy.yaml",
            remove,
            VALIDATOR.validate_policy_and_requirement_semantics,
        )
        self.assertTrue(any("omit mandatory controls" in error for error in validation.errors))

    def test_lifecycle_gate_rejects_completed_deletion_with_failed_serving_block(self):
        def fail_block(document):
            document["servingState"] = "failed"

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": fail_block},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("does not keep serving blocked" in error for error in validation.errors))

    def test_protected_resource_gate_covers_body_addressed_read_plan_validation(self):
        def expose(text):
            marker = "operationId: validateReadPlan"
            start = text.index(marker)
            end = text.index("  /read-plans/{planId}/execute:", start)
            block = text[start:end].replace(
                "'404': { $ref: '#/components/responses/ProtectedResourceUnavailable' }",
                "'403': { $ref: '#/components/responses/Forbidden' }",
            )
            return text[:start] + block + text[end:]

        validation = self.run_against_mutated_text(
            "contracts/api.openapi.yaml",
            expose,
            VALIDATOR.validate_protected_resource_errors,
        )
        self.assertTrue(any("validate" in error.lower() or "distinguishable 403" in error for error in validation.errors))

    def test_secret_scanner_detects_unlabelled_hex_credentials(self):
        self.assertTrue(
            VALIDATOR.detects_secret_like_input(
                "9f2c7a1d4e8b6c0f3a5d7e9b1c4f6a8d2e5b7c9f0a3d6e8b1c4f7a9d2e5b8c0f"
            )
        )

    def test_trusted_receipts_reject_redaction_before_issuer_validity(self):
        def delay(document):
            issuer = next(row for row in document["issuers"] if "redaction" in row["purposes"])
            issuer["validFrom"] = "2026-01-01T00:02:00Z"

        validation = self.run_against_mutated_package(
            {"security/trusted-issuers.json": delay},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("redaction receipt was signed outside" in error for error in validation.errors))

    def test_trusted_receipts_reject_cross_scope_grant_outside_issuer_validity(self):
        def delay(document):
            issuer = next(row for row in document["issuers"] if "cross-scope-authorization" in row["purposes"])
            issuer["validFrom"] = "2026-01-01T00:03:30Z"

        validation = self.run_against_mutated_package(
            {"security/trusted-issuers.json": delay},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("cross-scope-authorization receipt was signed outside" in error for error in validation.errors))

    def test_capability_negotiation_detects_connector_capability_hash_drift(self):
        def drift(document):
            document["connectorVersion"] = "2.0.0"

        validation = self.run_against_mutated_package(
            {"examples/source-descriptor.json": drift},
            VALIDATOR.validate_capability_negotiation,
        )
        self.assertTrue(any("connector capability hash is not derivable" in error for error in validation.errors))

    def test_projection_seal_detects_connector_coordinate_drift(self):
        def drift(document):
            document["connectorCapabilityHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/capability-manifest.json": drift},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("connectorCapabilityHash differs" in error for error in validation.errors))

    def test_run_accounting_detects_stage_output_hash_drift(self):
        def drift(document):
            document["receipts"][0]["outputs"][0]["contentHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/stage-receipt-bundle.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("output hash differs" in error for error in validation.errors))

    def test_run_accounting_detects_stage_dependency_receipt_drift(self):
        def drift(document):
            document["receipts"][1]["dependencyReceiptIds"] = []

        validation = self.run_against_mutated_package(
            {"examples/stage-receipt-bundle.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("dependency receipts differ" in error for error in validation.errors))

    def test_run_accounting_detects_output_item_count_drift(self):
        def drift(document):
            document["receipts"][0]["outputs"][0]["itemCount"] = 2

        validation = self.run_against_mutated_package(
            {"examples/stage-receipt-bundle.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("output item counts do not reconcile" in error for error in validation.errors))

    def test_run_accounting_detects_run_level_coverage_drift(self):
        def drift(document):
            document["coverage"]["assetsCompleted"] = 999

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("asset coverage does not reconcile" in error for error in validation.errors))

    def test_pipeline_gate_detects_stage_requiredness_drift_in_schema(self):
        def drift(document):
            document["properties"]["stages"]["prefixItems"][14]["allOf"][1]["properties"]["required"]["const"] = False

        validation = self.run_against_mutated_package(
            {"contracts/profiling-run.schema.json": drift},
            VALIDATOR.validate_pipeline_registries,
        )
        self.assertTrue(any("schema requiredness differs" in error for error in validation.errors))

    def test_execution_receipts_detect_changed_model_deployment_identity(self):
        def drift(document):
            document["modelDeploymentHash"] = "9" * 64

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": drift},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("keySha256 is not derivable" in error for error in validation.errors))

    def test_execution_receipts_reject_post_execution_model_admission(self):
        def drift(document):
            document["admission"]["decidedAt"] = "2026-01-01T00:06:00Z"

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": drift},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("timestamps are out of order" in error for error in validation.errors))

    def test_execution_receipts_reject_incompatible_model_region(self):
        def drift(document):
            document["admission"]["deploymentRegion"] = "incompatible-region"

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": drift},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("incompatible with source residency" in error for error in validation.errors))

    def test_retrieval_gate_detects_fabricated_caveat_omission_count(self):
        def drift(document):
            document["coverageReceipt"]["omittedBySection"]["caveats"] = 999

        validation = self.run_against_mutated_package(
            {"examples/retrieval-bundle.json": drift},
            VALIDATOR.validate_retrieval_bundle,
        )
        self.assertTrue(any("caveat accounting does not reconcile" in error for error in validation.errors))

    def test_retrieval_gate_detects_partial_coordinate_drift(self):
        def drift(document):
            document["coordinate"]["methodSetHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/retrieval-bundle.json": drift},
            VALIDATOR.validate_retrieval_bundle,
        )
        self.assertTrue(any("coordinate differs" in error for error in validation.errors))

    def test_projection_privacy_detects_unregistered_extension_schema(self):
        def drift(document):
            document["sourceExtensions"][0]["payloadSchemaId"] = "unregistered-schema"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_projection_privacy,
        )
        self.assertTrue(any("unregistered payload schema" in error for error in validation.errors))

    def test_trusted_receipts_detect_extension_asset_replay(self):
        def drift(document):
            document["sourceExtensions"][0]["assetId"] = "work-events"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("complete extension envelope" in error for error in validation.errors))

    def test_evidence_integrity_detects_logical_key_sample_plan_drift(self):
        def drift(document):
            document["records"][0]["logicalKey"]["samplePlanHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/evidence-bundle.json": drift},
            VALIDATOR.validate_evidence_integrity,
        )
        self.assertTrue(any("sample plan hash differs" in error for error in validation.errors))

    def test_lifecycle_inventory_detects_forged_inventory_hash(self):
        def drift(document):
            document["inventoryHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": drift},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("inventory hash is not derivable" in error for error in validation.errors))

    def test_profile_contract_rejects_empty_field_statistics(self):
        profile = self.load("examples/profile-manifest.json")
        schema = self.load("contracts/profile-manifest.schema.json")
        mutated = copy.deepcopy(profile)
        mutated["assets"][0]["fields"][0]["statistics"] = {}
        errors = self.validate(mutated, schema, "contracts/profile-manifest.schema.json")
        self.assertTrue(any("missing required property method" in error for error in errors))

    def test_example_references_detect_unknown_semantic_role(self):
        def drift(document):
            document["assets"][0]["fields"][0]["semanticRoles"] = ["unknown-new-role"]

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("unknown semantic roles" in error for error in validation.errors))

    def test_example_references_detect_relationship_cardinality_drift(self):
        def drift(document):
            document["relationships"][0]["cardinality"] = "many-to-many"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("cardinality differs" in error for error in validation.errors))

    def test_example_references_detect_relationship_normalization_drift(self):
        def drift(document):
            document["relationships"][0]["normalization"][0]["family"] = "canonical-identifier"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("normalization differs" in error for error in validation.errors))

    def test_example_references_detect_relationship_operation_drift(self):
        def drift(document):
            document["relationships"][0]["recommendedOperation"] = "inner"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("recommended operation differs" in error for error in validation.errors))

    def test_example_references_detect_dangling_business_metric(self):
        def drift(document):
            document["businessModel"]["scenarios"][0]["candidateMetricIds"] = ["missing-metric"]

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("references missing metrics" in error for error in validation.errors))

    def test_example_references_require_nonempty_model_pattern_vector(self):
        def drift(document):
            document["modelPatterns"] = []

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": drift},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("model pattern" in error.lower() for error in validation.errors))

    def test_read_plan_binding_detects_wrong_salted_subject_hash(self):
        def drift(document):
            document["callerSubjectHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/read-plan-validation-receipt.json": drift},
            VALIDATOR.validate_read_plan_bindings,
        )
        self.assertTrue(any("callerSubjectHash mismatch" in error for error in validation.errors))

    def test_projection_privacy_detects_extension_schema_hash_drift(self):
        def drift(document):
            document["schemas"][0]["schemaHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"config/extension-schema-registry.json": drift},
            VALIDATOR.validate_projection_privacy,
        )
        self.assertTrue(any("registry hash mismatch" in error for error in validation.errors))

    def test_traceability_detects_duplicate_mapping_that_cannot_inflate_coverage(self):
        def duplicate(document):
            document["requirements"][0]["bdd"].append(copy.deepcopy(document["requirements"][0]["bdd"][0]))

        validation = self.run_against_mutated_package(
            {"requirements/catalog.json": duplicate},
            VALIDATOR.validate_features_and_traceability,
        )
        self.assertTrue(any("duplicate BDD mappings" in error for error in validation.errors))

    def test_artifact_inventory_requires_the_shared_control_verifier(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            (target / "scripts" / "validation_control.py").unlink()
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                VALIDATOR.validate_artifacts(validation)
            finally:
                VALIDATOR.ROOT = original_root
        self.assertTrue(any("scripts/validation_control.py" in error for error in validation.errors))

    def test_validation_control_rejects_unsigned_floor_and_test_count_changes(self):
        mutations = {
            "minimum test count": lambda document: document.update(minimumTestCount=1),
            "gate floor": lambda document: document["gateMinimumChecks"].update(validate_artifacts=1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                target = Path(scratch) / "kit"
                shutil.copytree(ROOT, target)
                path = target / "config" / "validation-gates.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                mutate(document)
                path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    VALIDATOR.load_verified_control(target)

    def test_validation_control_rejects_signature_tampering(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            path = target / "config" / "validation-gates.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            signature = bytearray(base64.b64decode(document["signature"], validate=True))
            signature[0] ^= 1
            document["signature"] = base64.b64encode(signature).decode()
            path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "signature is invalid"):
                VALIDATOR.load_verified_control(target)

    def test_validation_control_rejects_signed_nonpositive_floors(self):
        mutations = {
            "test floor": lambda document: document.update(minimumTestCount=0),
            "gate floor": lambda document: document["gateMinimumChecks"].update(validate_artifacts=0),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                scratch_path = Path(scratch)
                target = scratch_path / "kit"
                shutil.copytree(ROOT, target)
                private_key, issuer_key_id, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
                path = target / "config" / "validation-gates.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                mutate(document)
                self.reseal_validation_control(document, private_key, issuer_key_id)
                path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                control_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError, "must be positive"):
                    VALIDATOR.load_verified_control(
                        target,
                        issuer_registry_path=registry_path,
                        expected_registry_sha256=registry_hash,
                        expected_control_sha256=control_hash,
                        require_external=True,
                    )

    def test_production_control_rejects_package_local_issuer_replacement_and_reseal(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            private_key = Ed25519PrivateKey.generate()
            issuer_key_id = "attacker-controlled-issuer"
            registry = {
                "registryVersion": "1.0.0",
                "registryUse": "production",
                "issuers": [
                    {
                        "issuerKeyId": issuer_key_id,
                        "algorithm": "ed25519",
                        "publicKeyBase64": base64.b64encode(
                            private_key.public_key().public_bytes(
                                encoding=serialization.Encoding.Raw,
                                format=serialization.PublicFormat.Raw,
                            )
                        ).decode(),
                        "purposes": ["validation-control"],
                        "validFrom": "2026-01-01T00:00:00Z",
                        "validUntil": "2027-01-01T00:00:00Z",
                    }
                ],
            }
            registry_path = target / "security" / "trusted-issuers.json"
            raw = (json.dumps(registry, indent=2) + "\n").encode()
            registry_path.write_bytes(raw)
            control_path = target / "config" / "validation-gates.json"
            control = json.loads(control_path.read_text(encoding="utf-8"))
            control["gates"] = ["validate_artifacts"]
            control["gateMinimumChecks"] = {"validate_artifacts": 1}
            control["minimumTestCount"] = 1
            self.reseal_validation_control(control, private_key, issuer_key_id)
            control_path.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            control_hash = hashlib.sha256(control_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "outside the package"):
                VALIDATOR.load_verified_control(
                    target,
                    issuer_registry_path=registry_path,
                    expected_registry_sha256=hashlib.sha256(raw).hexdigest(),
                    expected_control_sha256=control_hash,
                    require_external=True,
                )

    def test_runtime_dispatch_enforces_each_gate_check_floor(self):
        original_gates = VALIDATOR.GATES
        original_gate = VALIDATOR.validate_artifacts
        original_loader = VALIDATOR.load_verified_control
        VALIDATOR.GATES = ["validate_artifacts"]
        VALIDATOR.validate_artifacts = lambda validation: validation.check(True, "seeded check")
        VALIDATOR.load_verified_control = lambda *args, **kwargs: {
            "gates": ["validate_artifacts"],
            "gateMinimumChecks": {"validate_artifacts": 2},
        }
        try:
            validation = VALIDATOR.Validation()
            VALIDATOR.run_declared_gates(validation)
        finally:
            VALIDATOR.GATES = original_gates
            VALIDATOR.validate_artifacts = original_gate
            VALIDATOR.load_verified_control = original_loader
        self.assertTrue(any("expected at least 2" in error for error in validation.errors))

    def test_fail_closed_runner_rejects_skipped_tests(self):
        skipped_suite = """import unittest

class SeededSkip(unittest.TestCase):
    @unittest.skip(\"seeded skip\")
    def test_seeded_skip(self):
        self.fail(\"must not execute\")
"""
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            target = scratch_path / "kit"
            shutil.copytree(ROOT, target)
            private_key, issuer_key_id, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
            (target / "tests" / "test_validate_package.py").write_text(skipped_suite, encoding="utf-8")
            control_path = target / "config" / "validation-gates.json"
            control = json.loads(control_path.read_text(encoding="utf-8"))
            control["minimumTestCount"] = 1
            self.bind_test_files(control, target)
            self.reseal_validation_control(control, private_key, issuer_key_id)
            control_path.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            control_hash = hashlib.sha256(control_path.read_bytes()).hexdigest()
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/run_tests.py",
                    "--trust-mode",
                    "production",
                    "--trust-registry",
                    str(registry_path),
                    "--trust-registry-sha256",
                    registry_hash,
                    "--validation-control-sha256",
                    control_hash,
                    "--validation-verifier-sha256",
                    self.validation_verifier_hash(target),
                ],
                cwd=target,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("1 test(s) were skipped", result.stdout + result.stderr)

    def test_projection_seal_detects_consistent_source_connector_substitution(self):
        def substitute(document):
            import rfc8785

            document["connectorId"] = "connectors/alternate-reader-v1"
            document["connectorVersion"] = "2.0.0"
            preimage = {
                "connectorId": document["connectorId"],
                "connectorVersion": document["connectorVersion"],
                "capabilities": sorted(document["connectorDeclaredCapabilities"]),
            }
            document["connectorCapabilityHash"] = hashlib.sha256(rfc8785.dumps(preimage)).hexdigest()

        validation = self.run_against_mutated_package(
            {"examples/source-descriptor.json": substitute},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("Registered source connectorId differs" in error for error in validation.errors))

    def test_projection_seal_detects_profile_connector_substitution(self):
        def substitute(document):
            document["connectorId"] = "connectors/alternate-reader-v1"

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": substitute},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("Registered source connectorId differs" in error for error in validation.errors))

    def test_run_accounting_derives_output_count_from_the_artifact_selector(self):
        def substitute_selector(document):
            receipt = next(row for row in document["receipts"] if row["stageId"] == "detect-model-patterns")
            receipt["outputs"][0]["countSelector"]["kind"] = "profile-business-concepts"

        validation = self.run_against_mutated_package(
            {"examples/stage-receipt-bundle.json": substitute_selector},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("derived profile-business-concepts count" in error for error in validation.errors))

    def test_run_accounting_rejects_duplicate_output_id_or_uri_bindings(self):
        mutations = {
            "artifact ID": lambda outputs: outputs[1].update(artifactId=outputs[0]["artifactId"]),
            "artifact URI": lambda outputs: outputs[1].update(artifactUri=outputs[0]["artifactUri"]),
        }
        expected = {
            "artifact ID": "duplicate output artifact IDs",
            "artifact URI": "duplicate output artifact URIs",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                def duplicate(document, mutate=mutate):
                    receipt = next(row for row in document["receipts"] if row["stageId"] == "build-manifests")
                    mutate(receipt["outputs"])

                validation = self.run_against_mutated_package(
                    {"examples/stage-receipt-bundle.json": duplicate},
                    VALIDATOR.validate_run_accounting,
                )
                self.assertTrue(any(expected[name] in error for error in validation.errors))

    def test_run_accounting_rejects_stage_detail_outcome_drift(self):
        def drift(document):
            stage = next(row for row in document["outputs"] if row["stageId"] == "quality-freshness")
            stage["items"][1]["outcome"] = "completed"

        validation = self.run_against_mutated_package(
            {"examples/stage-output-details.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("completed count differs from receipt work" in error for error in validation.errors))
        self.assertTrue(any("unavailable count differs from receipt work" in error for error in validation.errors))

    def test_nonvalidated_relationship_still_requires_evidence_parity(self):
        def make_insufficient(document):
            record = next(row for row in document["records"] if row["kind"] == "relationship-validation")
            record["payload"]["validationOutcome"] = "insufficient-support"

        def drift_projection(document):
            document["relationships"][0]["validationStatus"] = "hypothesis"
            document["relationships"][0]["recommendedOperation"] = "inner"

        validation = self.run_against_mutated_package(
            {
                "examples/evidence-bundle.json": make_insufficient,
                "examples/profile-manifest.json": drift_projection,
            },
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("recommended operation differs" in error for error in validation.errors))

    def test_traceability_detects_semantic_criterion_tag_substitution(self):
        def substitute(text):
            return text.replace("@FR-001-AC-01", "@FR-001-AC-02", 1)

        validation = self.run_against_mutated_text(
            "features/source-onboarding.feature",
            substitute,
            VALIDATOR.validate_features_and_traceability,
        )
        self.assertTrue(any("lacks semantic criterion tag @FR-001-AC-01" in error for error in validation.errors))

    def test_execution_receipts_detect_model_admission_identity_drift(self):
        def drift(document):
            document["providerId"] = "alternate-semantic-provider"

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": drift},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("admission provider differs" in error for error in validation.errors))
        self.assertTrue(any("keySha256 is not derivable" in error for error in validation.errors))

    def test_execution_receipts_reject_expired_cache_write(self):
        def expire(document):
            document["cache"]["expiresAt"] = document["completedAt"]

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": expire},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("cache expiry does not follow" in error for error in validation.errors))

    def test_execution_receipts_detect_evidence_set_drift(self):
        def drift(document):
            document["evidenceSetHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/model-execution.json": drift},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertTrue(any("evidenceSetHash is not derived" in error for error in validation.errors))

    def test_api_receipts_detect_operation_hash_drift(self):
        def drift(document):
            document["operationHash"] = "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/read-execution-result.json": drift},
            VALIDATOR.validate_api_receipts,
        )
        self.assertTrue(any("operationHash differs" in error for error in validation.errors))

    def test_api_receipts_detect_operation_target_drift(self):
        def drift(document):
            document["targetId"] = "work-records"

        validation = self.run_against_mutated_package(
            {"examples/read-execution-result.json": drift},
            VALIDATOR.validate_api_receipts,
        )
        self.assertTrue(any("targetId differs" in error for error in validation.errors))

    def test_secret_scanner_detects_unhyphenated_32_character_hex(self):
        self.assertTrue(VALIDATOR.detects_secret_like_input("0123456789abcdef0123456789abcdef"))
        self.assertFalse(VALIDATOR.detects_secret_like_input("12341234123412341234123412341234"))

    def test_example_references_reject_removal_of_each_model_pattern_kind(self):
        for kind in ("storage", "hierarchy", "graph", "dimensional", "temporal"):
            with self.subTest(kind=kind):
                def remove(document, kind=kind):
                    document["modelPatterns"] = [
                        pattern for pattern in document["modelPatterns"]
                        if pattern["kind"] != kind
                    ]

                validation = self.run_against_mutated_package(
                    {"examples/profile-manifest.json": remove},
                    VALIDATOR.validate_example_references,
                )
                self.assertTrue(any("do not cover the complete taxonomy" in error for error in validation.errors))

    def test_profile_contract_rejects_malformed_details_for_each_model_pattern_kind(self):
        required_detail = {
            "storage": "layout",
            "hierarchy": "levelPaths",
            "graph": "nodeAssetIds",
            "dimensional": "factAssetIds",
            "temporal": "timePaths",
        }
        schema = self.load("contracts/profile-manifest.schema.json")
        for kind, field in required_detail.items():
            with self.subTest(kind=kind):
                profile = self.load("examples/profile-manifest.json")
                pattern = next(row for row in profile["modelPatterns"] if row["kind"] == kind)
                del pattern["details"][field]
                errors = self.validate(profile, schema, "contracts/profile-manifest.schema.json")
                self.assertTrue(any(f"missing required property {field}" in error for error in errors), errors)

    def test_example_references_reject_dangling_details_for_each_model_pattern_kind(self):
        mutations = {
            "storage": ("identityPaths", ["missing-asset.MissingField"], "references missing field path"),
            "hierarchy": ("levelPaths", ["missing-asset.MissingField"], "references missing field path"),
            "graph": ("edgeRelationshipIds", ["missing-relationship"], "references missing relationships"),
            "dimensional": ("factAssetIds", ["missing-asset"], "references missing assets"),
            "temporal": ("timePaths", ["missing-asset.MissingField"], "references missing field path"),
        }
        for kind, (field, value, expected) in mutations.items():
            with self.subTest(kind=kind):
                def drift(document, kind=kind, field=field, value=value):
                    pattern = next(row for row in document["modelPatterns"] if row["kind"] == kind)
                    pattern["details"][field] = value

                validation = self.run_against_mutated_package(
                    {"examples/profile-manifest.json": drift},
                    VALIDATOR.validate_example_references,
                )
                self.assertTrue(any(expected in error for error in validation.errors), validation.errors)

    def test_example_references_require_results_for_every_passed_statistic_family(self):
        result_fields = {
            "missingness": ("nullRatio", "count"),
            "cardinality": ("distinctCount",),
            "distribution": ("entropy", "mean", "quantiles", "concentration"),
            "format": ("formatShares", "minimumLength"),
            "temporal": ("minimumTime", "cadenceSeconds"),
            "outlier": ("outlierRatio",),
            "nesting": ("nestingMaximumDepth", "variantCount"),
        }
        for family, fields in result_fields.items():
            with self.subTest(family=family):
                def strip(document, family=family, fields=fields):
                    statistics = next(
                        field["statistics"]
                        for asset in document["assets"]
                        for field in asset["fields"]
                        if any(
                            row["family"] == family and row["outcome"] == "passed"
                            for row in field["statistics"]["families"]
                        )
                    )
                    for field in fields:
                        statistics.pop(field, None)

                validation = self.run_against_mutated_package(
                    {"examples/profile-manifest.json": strip},
                    VALIDATOR.validate_example_references,
                )
                self.assertTrue(
                    any(f"passed {family}" in error for error in validation.errors),
                    validation.errors,
                )

    def test_example_references_reject_wrong_kind_and_dangling_business_links(self):
        mutations = {
            "event entity kind": (
                lambda business: business["events"][0].update(subjectEntityIds=["metric-change-count"]),
                "wrong-kind entity",
            ),
            "process event kind": (
                lambda business: business["processes"][0].update(startEventIds=["entity-work-record"]),
                "wrong-kind events",
            ),
            "process measure kind": (
                lambda business: business["processes"][0].update(durationMeasureIds=["dimension-scope"]),
                "wrong-kind measures",
            ),
            "scenario measure kind": (
                lambda business: business["scenarios"][0].update(requiredMeasureIds=["dimension-scope"]),
                "references missing measures",
            ),
            "scenario dimension kind": (
                lambda business: business["scenarios"][0].update(requiredDimensionIds=["measure-change-count"]),
                "references missing dimensions",
            ),
            "glossary concept": (
                lambda business: business["glossary"][0].update(mappedConceptIds=["missing-concept"]),
                "references missing concepts",
            ),
            "glossary metric kind": (
                lambda business: business["glossary"][0].update(mappedMetricIds=["measure-change-count"]),
                "references missing metrics",
            ),
            "glossary field path": (
                lambda business: business["glossary"][0].update(mappedFieldPaths=["work-events.MissingField"]),
                "references missing field path",
            ),
            "glossary source": (
                lambda business: business["glossary"][0].update(sourceRefs=["missing-asset"]),
                "references missing source assets",
            ),
        }
        for name, (mutate, expected) in mutations.items():
            with self.subTest(name=name):
                def drift(document, mutate=mutate):
                    mutate(document["businessModel"])

                validation = self.run_against_mutated_package(
                    {"examples/profile-manifest.json": drift},
                    VALIDATOR.validate_example_references,
                )
                self.assertTrue(any(expected in error for error in validation.errors), validation.errors)

    def test_run_accounting_requires_boundary_open_before_discovery(self):
        def drift(document):
            document["sourceBoundary"]["openedAt"] = "2026-01-01T00:00:15Z"

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("discovery starts before" in error.lower() for error in validation.errors))

    def test_run_accounting_rejects_final_version_on_pre_discovery_receipt(self):
        def drift(document):
            receipt = next(row for row in document["receipts"] if row["stageId"] == "open-source-boundary")
            receipt["sourceVersionStatus"] = "final"
            receipt["sourceVersion"] = "sha256:" + "0" * 64

        validation = self.run_against_mutated_package(
            {"examples/stage-receipt-bundle.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("falsely claims a final source version" in error for error in validation.errors))

    def test_run_accounting_derives_source_version_from_bounded_structure(self):
        def drift(document):
            document["assets"][0]["fields"][0]["physicalType"] = "integer"

        validation = self.run_against_mutated_package(
            {"examples/source-structure.json": drift},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("structure hash is not derivable" in error for error in validation.errors))

    def test_projection_seal_requires_every_registered_index_kind(self):
        def remove(document):
            document["indexes"] = [row for row in document["indexes"] if row["kind"] != "faceted"]

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": remove},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("complete index registry" in error for error in validation.errors))

    def test_production_trust_requires_external_registry_and_hash_pin(self):
        control_hash = hashlib.sha256((ROOT / "config" / "validation-gates.json").read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "outside the package"):
            VALIDATOR.load_verified_control(
                ROOT,
                issuer_registry_path=ROOT / "security" / "trusted-issuers.json",
                expected_registry_sha256=hashlib.sha256((ROOT / "security" / "trusted-issuers.json").read_bytes()).hexdigest(),
                expected_control_sha256=control_hash,
                require_external=True,
            )

    def test_production_trust_rejects_multi_purpose_or_reused_issuer_keys(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            _, _, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
            document = json.loads(registry_path.read_text(encoding="utf-8"))
            document["issuers"][0]["purposes"].append("publication")
            raw = (json.dumps(document, indent=2) + "\n").encode()
            registry_path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "exactly one purpose"):
                VALIDATOR.load_trusted_issuers(
                    ROOT,
                    issuer_registry_path=registry_path,
                    expected_registry_sha256=hashlib.sha256(raw).hexdigest(),
                    require_external=True,
                )

    def test_projection_privacy_rejects_secret_or_direct_identifier_in_served_text(self):
        mutations = {
            "secret": ("password=SensitiveValue-123456789", "secret-like material"),
            "email": ("Contact analyst@example.invalid", "direct identifier"),
        }
        for name, (value, expected) in mutations.items():
            with self.subTest(name=name):
                def inject(document, value=value):
                    document["summary"] = value

                validation = self.run_against_mutated_package(
                    {"examples/profile-manifest.json": inject},
                    VALIDATOR.validate_projection_privacy,
                )
                self.assertTrue(any(expected in error for error in validation.errors), validation.errors)

    def test_traceability_detects_mapping_and_tag_substitution_via_semantic_seal(self):
        def remap(document):
            requirement = next(row for row in document["requirements"] if row["id"] == "FR-001")
            requirement["bdd"][0]["scenarioRef"] = "source-onboarding:register an authorized source"

        def retag(text):
            marker = "  Scenario: register an authorized source"
            return text.replace(marker, "  @FR-001-AC-01\n" + marker, 1)

        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            catalog_path = target / "requirements" / "catalog.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            remap(catalog)
            catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
            feature_path = target / "features" / "source-onboarding.feature"
            feature_path.write_text(retag(feature_path.read_text(encoding="utf-8")), encoding="utf-8")
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                VALIDATOR.validate_features_and_traceability(validation)
            finally:
                VALIDATOR.ROOT = original_root
        self.assertTrue(any("semantic binding hash mismatch" in error for error in validation.errors))

    def test_read_plan_bindings_reject_missing_malformed_or_oversized_parameters(self):
        mutations = {
            "missing": lambda document: document["parameters"].pop("scopeId"),
            "malformed": lambda document: document["parameters"].update(fromTime="not-a-date"),
            "oversized": lambda document: document["parameters"].update(scopeId="x" * 101),
        }
        expected = {
            "missing": "parameter scopeId is missing",
            "malformed": "parameter fromTime does not match declared type",
            "oversized": "parameter scopeId exceeds maximumLength",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/read-plan-validation-context.json": mutate},
                    VALIDATOR.validate_read_plan_bindings,
                )
                self.assertTrue(any(expected[name] in error for error in validation.errors), validation.errors)

    def test_read_execution_rejects_invalid_or_expired_receipt(self):
        mutations = {
            "invalid": ("examples/read-plan-validation-receipt.json", lambda document: document.update(valid=False), "decision is invalid"),
            "expired": ("examples/read-execution-result.json", lambda document: document.update(executedAt="2026-01-01T00:15:00Z"), "outside the validation receipt window"),
        }
        for name, (path, mutate, expected) in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {path: mutate},
                    VALIDATOR.validate_api_receipts,
                )
                self.assertTrue(any(expected in error for error in validation.errors), validation.errors)

    def test_read_execution_rejects_validated_limit_overruns(self):
        mutations = {
            "rows": (lambda receipt: receipt.update(maximumRows=1), "row limit"),
            "bytes": (lambda receipt: receipt.update(maximumBytes=1), "byte limit"),
            "duration": (lambda receipt: receipt.update(maximumDurationMilliseconds=1), "duration limit"),
        }
        for name, (mutate, expected) in mutations.items():
            with self.subTest(name=name):
                def lower(document, mutate=mutate):
                    mutate(document["estimatedCost"])

                validation = self.run_against_mutated_package(
                    {"examples/read-plan-validation-receipt.json": lower},
                    VALIDATOR.validate_api_receipts,
                )
                self.assertTrue(any(expected in error for error in validation.errors), validation.errors)

    def test_trusted_receipts_authenticate_read_plan_validation_decision(self):
        def tamper(document):
            signature = bytearray(base64.b64decode(document["signature"], validate=True))
            signature[0] ^= 1
            document["signature"] = base64.b64encode(signature).decode()

        validation = self.run_against_mutated_package(
            {"examples/read-plan-validation-receipt.json": tamper},
            VALIDATOR.validate_trusted_receipts,
        )
        self.assertTrue(any("read-plan-validation receipt signature verification failed" in error for error in validation.errors))

    def test_pending_running_and_resume_run_examples_are_contract_valid(self):
        schema = self.load("contracts/profiling-run.schema.json")
        for name in ("profiling-run-pending.json", "profiling-run-running.json", "profiling-run-resume.json"):
            with self.subTest(name=name):
                run = self.load(f"examples/{name}")
                self.assertEqual([], self.validate(run, schema, "contracts/profiling-run.schema.json"))

    def test_run_lifecycle_rejects_expired_or_mismatched_running_lease(self):
        mutations = {
            "mismatched": lambda document: document["lease"].update(fencingToken=document["fencingToken"] + 1),
            "expired": lambda document: document["lease"].update(expiresAt="2026-01-01T00:00:01Z"),
        }
        expected = {
            "mismatched": "lease fencing token differs",
            "expired": "lease is not valid at state observation time",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/profiling-run-running.json": mutate},
                    VALIDATOR.validate_run_lifecycle_examples,
                )
                self.assertTrue(any(expected[name] in error for error in validation.errors), validation.errors)

    def test_resume_run_rejects_unresolved_or_incompatible_checkpoint(self):
        mutations = {
            "predecessor": lambda document: document["resumeCheckpoint"].update(predecessorRunHash="0" * 64),
            "dependency": lambda document: document["resumeCheckpoint"].update(completedDependencyReceiptIds=[]),
        }
        expected = {
            "predecessor": "predecessor run hash mismatch",
            "dependency": "completed dependency receipts differ",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/profiling-run-resume.json": mutate},
                    VALIDATOR.validate_run_lifecycle_examples,
                )
                self.assertTrue(any(expected[name] in error for error in validation.errors), validation.errors)

    def test_projection_seal_requires_manifest_version_on_every_index(self):
        def remove(document):
            document["indexes"][0].pop("manifestVersion", None)

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": remove},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("index manifestVersion differs" in error for error in validation.errors), validation.errors)

    def test_read_plan_bindings_reject_limits_above_policy_ceiling(self):
        def inflate(document):
            document["limits"]["maximumBytes"] = 10**12

        validation = self.run_against_mutated_package(
            {"examples/read-plan.json": inflate},
            VALIDATOR.validate_read_plan_bindings,
        )
        self.assertTrue(any("Read-plan maximumBytes exceeds the policy ceiling" in error for error in validation.errors), validation.errors)

    def test_run_accounting_rejects_usage_above_policy_budget(self):
        def inflate(document):
            document["budget"]["usage"]["sourceBytesRead"] = document["budget"]["limits"]["sourceBytesRead"] + 1

        validation = self.run_against_mutated_package(
            {"examples/profiling-run.json": inflate},
            VALIDATOR.validate_run_accounting,
        )
        self.assertTrue(any("run budget sourceBytesRead exceeds its policy limit" in error for error in validation.errors), validation.errors)

    def test_lifecycle_inventory_reconciles_every_published_index(self):
        def omit(document):
            row = next(item for item in document["stores"] if item["storeKind"] == "temporal-index")
            row.update(artifactIds=[], artifactSetHash=hashlib.sha256(b"[]").hexdigest(), expected=0, deleted=0, state="not-applicable")

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": omit},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("temporal-index expected artifacts differ from the signed lifecycle inventory" in error for error in validation.errors), validation.errors)

    def test_lifecycle_inventory_rejects_all_zero_completion(self):
        def erase(document):
            for row in document["stores"]:
                row.update(
                    artifactIds=[],
                    artifactSetHash=hashlib.sha256(b"[]").hexdigest(),
                    expected=0,
                    deleted=0,
                    failed=0,
                    notFound=0,
                    remaining=0,
                    retainedByPolicy=0,
                    state="not-applicable",
                )

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": erase},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("expected artifacts differ from the signed lifecycle inventory" in error for error in validation.errors), validation.errors)

    def test_lifecycle_inventory_rejects_serving_blocked_after_cleanup(self):
        def reorder(document):
            document["servingBlockedAt"] = "2026-01-02T00:06:00Z"

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": reorder},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("Lifecycle timestamps are out of order" in error for error in validation.errors), validation.errors)

    def test_projection_privacy_does_not_trust_identifier_suffixes(self):
        def inject(document):
            document["columns"].append({"name": "userId", "physicalType": "string"})
            for row in document["rows"]:
                row["userId"] = "analyst@example.invalid"

        validation = self.run_against_mutated_package(
            {"examples/read-execution-result.json": inject},
            VALIDATOR.validate_projection_privacy,
        )
        self.assertTrue(any("direct identifier" in error and "userId" in error for error in validation.errors), validation.errors)

    def test_projection_privacy_requires_signed_ordinary_raw_value_scan(self):
        def report_collision(document):
            document["ordinaryRawValueCollisionCount"] = 1

        validation = self.run_against_mutated_package(
            {"examples/projection-safety-receipt.json": report_collision},
            VALIDATOR.validate_projection_privacy,
        )
        self.assertTrue(any("ordinary raw source-value collision" in error for error in validation.errors), validation.errors)

    def test_prompt_contracts_reject_inline_json_transport(self):
        def weaken(text):
            return text.replace("{{INPUT_PACK_BASE64}}", "{{EVIDENCE_PACK_JSON}}", 1)

        validation = self.run_against_mutated_text(
            "prompts/semantic-asset.prompt.md",
            weaken,
            VALIDATOR.validate_prompt_contracts,
        )
        self.assertTrue(any("base64 input placeholder" in error or "non-base64 input placeholders" in error for error in validation.errors), validation.errors)

    def test_production_control_requires_an_independent_control_byte_pin(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            private_key, issuer_key_id, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
            target = scratch_path / "kit"
            shutil.copytree(ROOT, target)
            control_path = target / "config" / "validation-gates.json"
            control = json.loads(control_path.read_text(encoding="utf-8"))
            self.reseal_validation_control(control, private_key, issuer_key_id)
            control_path.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "validation-control SHA-256 pin"):
                VALIDATOR.load_verified_control(
                    target,
                    issuer_registry_path=registry_path,
                    expected_registry_sha256=registry_hash,
                    require_external=True,
                )

    def test_read_plan_requested_coordinate_must_match_authorized_projection(self):
        def drift(document):
            document["requestedManifestVersion"] = "manifest-not-authorized"

        validation = self.run_against_mutated_package(
            {"examples/read-plan.json": drift},
            VALIDATOR.validate_read_plan_bindings,
        )
        self.assertTrue(any("requested manifest version differs" in error for error in validation.errors), validation.errors)

    def test_evidence_integrity_rejects_causally_impossible_dependency_time(self):
        def predate(document):
            record = next(row for row in document["records"] if row["kind"] == "identity")
            record["createdAt"] = "2025-12-31T23:59:00Z"

        validation = self.run_against_mutated_package(
            {"examples/evidence-bundle.json": predate},
            VALIDATOR.validate_evidence_integrity,
        )
        self.assertTrue(any("predates dependency" in error for error in validation.errors), validation.errors)

    def test_agent_response_contracts_bound_manifest_free_text(self):
        profile = self.load("examples/profile-manifest.json")
        profile_schema = self.load("contracts/profile-manifest.schema.json")
        capability = self.load("examples/capability-manifest.json")
        capability_schema = self.load("contracts/capability-manifest.schema.json")
        profile["assets"][0]["domain"] = "x" * 20001
        profile["assets"][0]["fields"][0]["businessMeaning"] = "x" * 20001
        capability["capabilities"][0]["description"] = "x" * 20001
        self.assertTrue(self.validate(profile, profile_schema, "contracts/profile-manifest.schema.json"))
        self.assertTrue(self.validate(capability, capability_schema, "contracts/capability-manifest.schema.json"))

    def test_benchmark_governance_has_an_executable_complete_comparison(self):
        result = subprocess.run(
            [sys.executable, "scripts/evaluate_benchmark.py", "benchmark/corpus.json", "benchmark/comparison.json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("PASS BENCHMARK", result.stdout)

    def test_projection_privacy_rejects_hex_secret_in_source_row(self):
        def inject(document):
            document["rows"][0]["RecordId"] = "9f2c7a1d4e8b6c0f3a5d7e9b1c4f6a8d2e5b7c9f0a3d6e8b1c4f7a9d2e5b8c0f"

        validation = self.run_against_mutated_package(
            {"examples/read-execution-result.json": inject},
            VALIDATOR.validate_projection_privacy,
        )
        self.assertTrue(any("secret-like material" in error and "RecordId" in error for error in validation.errors), validation.errors)

    def test_benchmark_rejects_metric_arithmetic_or_failed_case(self):
        corpus = self.load("benchmark/corpus.json")
        mutations = {
            "metric": lambda comparison: comparison["baseline"]["precision"].update(numerator=1),
            "failed case": lambda comparison: comparison["caseResults"][0]["candidateExecution"].update(failed=1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                comparison = self.load("benchmark/comparison.json")
                mutate(comparison)
                self.assertTrue(BENCHMARK_SCORER.score(corpus, comparison))

    def test_benchmark_rejects_negative_and_out_of_range_metrics(self):
        corpus = self.load("benchmark/corpus.json")
        mutations = {
            "negative numerator": lambda comparison: comparison["baseline"]["latency"].update(numerator=-1, value=-1 / comparison["baseline"]["latency"]["denominator"]),
            "ratio above one": lambda comparison: comparison["candidate"]["precision"].update(numerator=2, denominator=1, value=2),
            "negative contribution": lambda comparison: comparison["caseResults"][0]["metricContributions"]["baseline"]["bytesRead"].update(numerator=-1, value=-1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                comparison = self.load("benchmark/comparison.json")
                mutate(comparison)
                errors = BENCHMARK_SCORER.score(corpus, comparison)
                self.assertTrue(any("negative numerator or value" in error or "ratio is outside 0..1" in error for error in errors), errors)

    def test_benchmark_rejects_every_nonfinite_numeric_metric_and_acceptance_bound(self):
        corpus = self.load("benchmark/corpus.json")
        mutations = {
            "aggregate numerator": lambda comparison, value: comparison["baseline"]["precision"].update(numerator=value),
            "aggregate denominator": lambda comparison, value: comparison["candidate"]["latency"].update(denominator=value),
            "aggregate value": lambda comparison, value: comparison["baseline"]["modelUsage"].update(value=value),
            "contribution numerator": lambda comparison, value: comparison["caseResults"][0]["metricContributions"]["candidate"]["recall"].update(numerator=value),
            "contribution denominator": lambda comparison, value: comparison["caseResults"][0]["metricContributions"]["baseline"]["bytesRead"].update(denominator=value),
            "contribution value": lambda comparison, value: comparison["caseResults"][0]["metricContributions"]["candidate"]["calibration"].update(value=value),
            "correctness bound": lambda comparison, value: comparison["acceptance"].update(maximumCorrectnessRegression=value),
            "calibration bound": lambda comparison, value: comparison["acceptance"].update(maximumCalibrationRegression=value),
        }
        for value in (math.nan, math.inf, -math.inf):
            for name, mutate in mutations.items():
                with self.subTest(value=value, location=name):
                    comparison = self.load("benchmark/comparison.json")
                    mutate(comparison, value)
                    errors = BENCHMARK_SCORER.score(corpus, comparison)
                    self.assertTrue(any("finite" in error for error in errors), errors)

    def test_benchmark_cli_rejects_nonstandard_json_constants_during_parsing(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as scratch:
                document = self.load("benchmark/comparison.json")
                document["acceptance"]["maximumCorrectnessRegression"] = constant
                comparison = json.dumps(document).replace(f'"{constant}"', constant)
                path = Path(scratch) / "comparison.json"
                path.write_text(comparison, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-B", "scripts/evaluate_benchmark.py", "benchmark/corpus.json", str(path)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("non-standard JSON constant", result.stdout + result.stderr)

    def test_benchmark_pointer_rejects_noncanonical_or_out_of_bounds_index(self):
        corpus = self.load("benchmark/corpus.json")
        comparison = self.load("benchmark/comparison.json")
        for pointer in ("/assets/01/assetId", "/assets/999/assetId"):
            with self.subTest(pointer=pointer):
                mutated = copy.deepcopy(corpus)
                mutated["cases"][0]["probe"]["pointer"] = pointer
                errors = BENCHMARK_SCORER.score(mutated, comparison, ROOT)
                self.assertTrue(any("fixture probe failed" in error for error in errors), errors)

    def test_benchmark_rejects_missing_or_changed_fixture(self):
        corpus = self.load("benchmark/corpus.json")
        comparison = self.load("benchmark/comparison.json")
        corpus["cases"][0]["fixtureRef"] = "package://examples/does-not-exist.json"
        self.assertTrue(any("fixture" in error for error in BENCHMARK_SCORER.score(corpus, comparison, ROOT)))

    def test_resume_checkpoint_rejects_impossible_chronology(self):
        def predate(document):
            document["resumeCheckpoint"]["createdAt"] = "2026-01-01T00:00:00Z"
            document["resumeCheckpoint"]["sealedAt"] = "2026-01-01T00:00:00Z"

        validation = self.run_against_mutated_package(
            {"examples/profiling-run-resume.json": predate},
            VALIDATOR.validate_run_lifecycle_examples,
        )
        self.assertTrue(any("checkpoint chronology" in error.lower() for error in validation.errors), validation.errors)

    def test_run_budget_rejects_unreported_exhaustion_or_future_stop(self):
        mutations = {
            "unreported": lambda document: document["budget"]["usage"].update(wallClockMilliseconds=document["budget"]["limits"]["wallClockMilliseconds"]),
            "future stop": lambda document: (
                document["budget"].update(exhaustedDimensions=["wallClockMilliseconds"], stoppedAt="2027-01-01T00:00:00Z"),
                document["budget"]["usage"].update(wallClockMilliseconds=document["budget"]["limits"]["wallClockMilliseconds"]),
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/profiling-run-running.json": mutate},
                    VALIDATOR.validate_run_lifecycle_examples,
                )
                self.assertTrue(any("budget" in error.lower() for error in validation.errors), validation.errors)

    def test_resume_checkpoint_preserves_item_progress_and_cumulative_budget(self):
        mutations = {
            "work progress": lambda document: document["resumeCheckpoint"]["workProgress"].update(completedItemCount=0),
            "budget reset": lambda document: document["budget"]["usage"].update(sourceBytesRead=0, wallClockMilliseconds=0),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/profiling-run-resume.json": mutate},
                    VALIDATOR.validate_run_lifecycle_examples,
                )
                self.assertTrue(any("work progress" in error.lower() or "cumulative budget" in error.lower() for error in validation.errors), validation.errors)

    def test_resume_progress_manifest_binds_predecessor_checkpoint_and_resumed_run(self):
        mutations = {
            "predecessor run": lambda document: document.update(runId="33333333-3333-4333-8333-333333333399"),
            "source": lambda document: document.update(sourceId="11111111-1111-4111-8111-111111111199"),
            "scope": lambda document: document.update(authorizationScopeId="other-scope"),
            "stage": lambda document: document.update(stageId="profile-statistics"),
            "candidate": lambda document: document.update(sourceVersionCandidate="other-generation"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/work-progress-manifest.json": mutate},
                    VALIDATOR.validate_run_lifecycle_examples,
                )
                self.assertTrue(any("work progress manifest binding" in error.lower() for error in validation.errors), validation.errors)

    def test_resume_progress_ids_are_globally_disjoint(self):
        def duplicate(document):
            document["pendingItemIds"] = [document["completedItemIds"][0]]

        validation = self.run_against_mutated_package(
            {"examples/work-progress-page-0001.json": duplicate},
            VALIDATOR.validate_run_lifecycle_examples,
        )
        self.assertTrue(any("work progress item ids" in error.lower() for error in validation.errors), validation.errors)

    def test_publication_rejects_nonmonotonic_pointer_transition(self):
        def stale(document):
            document["pointerTransition"]["observedPreviousFencingToken"] = document["fencingToken"]

        validation = self.run_against_mutated_package(
            {"examples/publication-receipt.json": stale},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("pointer transition" in error.lower() for error in validation.errors), validation.errors)

    def test_publication_pointer_id_is_coordinate_derived(self):
        def repoint(document):
            document["pointerTransition"]["pointerId"] = "current:other-source:other-scope"

        validation = self.run_against_mutated_package(
            {"examples/publication-receipt.json": repoint},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("pointer id" in error.lower() for error in validation.errors), validation.errors)

    def test_deletion_contract_supports_sharded_inventory_over_inline_limit(self):
        manifest = self.load("examples/deletion-inventory-manifest.json")
        schema = self.load("contracts/deletion-inventory-manifest.schema.json")
        self.assertEqual([], self.validate(manifest, schema, "contracts/deletion-inventory-manifest.schema.json"))
        self.assertGreater(manifest["artifactCount"], 100000)

    def test_deletion_inventory_has_a_policy_backed_global_limit(self):
        def exceed(document):
            document["artifactCount"] = 10001

        validation = self.run_against_mutated_package(
            {"examples/deletion-inventory-active.json": exceed},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("policy maximum" in error.lower() for error in validation.errors), validation.errors)

    def test_execution_budget_rejects_reverse_time_and_millisecond_mismatch(self):
        mutations = {
            "reverse": lambda document: document["records"][0].update(completedAt="2026-01-01T00:00:11Z"),
            "milliseconds": lambda document: next(row for row in document["records"] if row["scope"] == "stage").update(usage=59999),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/execution-budget-bundle.json": mutate},
                    VALIDATOR.validate_execution_receipts,
                )
                self.assertTrue(any("completes before it starts" in error.lower() or "elapsed milliseconds" in error.lower() for error in validation.errors), validation.errors)

    def test_execution_budget_rejects_records_after_or_beyond_capture_time(self):
        import rfc8785

        mutations = {
            "capture predates record start": lambda document: document.update(capturedAt="2025-12-31T23:59:59Z"),
            "record completes after capture": lambda document: document["records"][0].update(completedAt="2026-01-01T00:11:02Z"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                def mutate_and_rehash(document, mutate=mutate):
                    mutate(document)
                    document["contentHash"] = hashlib.sha256(rfc8785.dumps({key: value for key, value in document.items() if key != "contentHash"})).hexdigest()

                validation = self.run_against_mutated_package(
                    {"examples/execution-budget-bundle.json": mutate_and_rehash},
                    VALIDATOR.validate_execution_receipts,
                )
                self.assertTrue(any("capturedat" in error.lower() for error in validation.errors), validation.errors)

    def test_source_structure_respects_policy_cardinality_limits(self):
        mutations = {
            "assets": lambda document: document["assets"].extend(copy.deepcopy(document["assets"][0]) for _ in range(10000)),
            "fields": lambda document: document["assets"][0]["fields"].extend(copy.deepcopy(document["assets"][0]["fields"][0]) for _ in range(5000)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/source-structure.json": mutate},
                    VALIDATOR.validate_run_accounting,
                )
                self.assertTrue(any(f"maximum{name}per" in error.lower() for error in validation.errors), validation.errors)

    def test_receipt_signing_times_must_be_inside_purpose_issuer_validity(self):
        def invalidate(document):
            for issuer in document["issuers"]:
                if issuer["issuerKeyId"] in {"conformance-lifecycle-deletion-v1", "conformance-projection-safety-v1"}:
                    issuer["validUntil"] = "2026-01-01T00:00:00Z"

        for checker in (VALIDATOR.validate_lifecycle_inventory, VALIDATOR.validate_projection_privacy):
            with self.subTest(checker=checker.__name__):
                validation = self.run_against_mutated_package(
                    {"security/trusted-issuers.json": invalidate},
                    checker,
                )
                self.assertTrue(any("issuer validity" in error.lower() for error in validation.errors), validation.errors)

    def test_package_inventory_rejects_undeclared_governed_and_compiled_cache_files(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            (target / "contracts" / "undeclared.schema.json").write_text("{}\n", encoding="utf-8")
            (target / "CodeReview" / "temporary-review.md").write_text("review\n", encoding="utf-8")
            (target / "scripts" / "__pycache__").mkdir()
            (target / "scripts" / "__pycache__" / "temporary.pyc").write_bytes(b"cache")
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                VALIDATOR.validate_artifacts(validation)
            finally:
                VALIDATOR.ROOT = original_root
        self.assertTrue(any("undeclared package artifact: contracts/undeclared.schema.json" in error.lower() for error in validation.errors), validation.errors)
        self.assertTrue(any("forbidden compiled/cache artifact: scripts/__pycache__/temporary.pyc" in error.lower() for error in validation.errors), validation.errors)
        self.assertFalse(any("temporary-review" in error for error in validation.errors), validation.errors)

    def test_dynamic_validator_uses_package_local_validation_control(self):
        expected = (ROOT / "scripts" / "validation_control.py").resolve()
        verifier = VALIDATOR.load_validation_verifier()
        for function in (verifier.load_trusted_issuers, verifier.load_verified_control):
            self.assertEqual(expected, Path(inspect.getsourcefile(function)).resolve())

    def test_nonterminal_deletion_rejects_enumeration_after_cleanup_start(self):
        def reorder(document):
            document["deletionState"] = "running"
            document["completedAt"] = None
            document["stores"][0]["enumeratedAt"] = "2026-01-02T00:00:04Z"

        validation = self.run_against_mutated_package(
            {"examples/deletion-receipt.json": reorder},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("before deletion started" in error for error in validation.errors), validation.errors)

    def test_evidence_response_is_bounded_and_provenance_marked(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_agent_response_bounds(validation)
        self.assertEqual([], validation.errors)
        response = self.load("examples/evidence-response.json")
        self.assertEqual("source-derived", response["responsePolicy"]["defaultContentProvenance"])

    def test_runner_rejects_replaced_verifier_and_191_vacuous_tests_with_original_external_pins(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            target = scratch_path / "kit"
            shutil.copytree(ROOT, target)
            private_key, issuer_key_id, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
            verifier_hash = self.validation_verifier_hash(target)
            control_path = target / "config" / "validation-gates.json"
            control = json.loads(control_path.read_text(encoding="utf-8"))
            self.reseal_validation_control(control, private_key, issuer_key_id)
            control_path.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            control_hash = hashlib.sha256(control_path.read_bytes()).hexdigest()

            fake_verifier = """import json

def load_verified_control(root, **kwargs):
    return json.loads((root / "config" / "validation-gates.json").read_text(encoding="utf-8"))
"""
            (target / "scripts" / "validation_control.py").write_text(fake_verifier, encoding="utf-8")
            test_path = target / "tests" / "test_validate_package.py"
            vacuous = "import unittest\n\nclass Vacuous(unittest.TestCase):\n" + "".join(
                f"    def test_replacement_{index:03d}(self): self.assertTrue(True)\n"
                for index in range(191)
            )
            test_path.write_text(vacuous, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/run_tests.py",
                    "--trust-mode", "production",
                    "--trust-registry", str(registry_path),
                    "--trust-registry-sha256", registry_hash,
                    "--validation-control-sha256", control_hash,
                    "--validation-verifier-sha256", verifier_hash,
                ],
                cwd=target,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("validation verifier SHA-256 does not match", result.stdout + result.stderr)

    def test_production_runner_rejects_missing_validation_verifier_pin(self):
        result = subprocess.run(
            [
                sys.executable,
                "scripts/run_tests.py",
                "--trust-mode", "production",
                "--trust-registry", "outside-package.json",
                "--trust-registry-sha256", "0" * 64,
                "--validation-control-sha256", "0" * 64,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("--validation-verifier-sha256", result.stdout + result.stderr)

    def test_production_validator_rejects_missing_validation_verifier_pin(self):
        result = subprocess.run(
            [
                sys.executable,
                "scripts/validate_package.py",
                "--trust-mode", "production",
                "--trust-registry", "outside-package.json",
                "--trust-registry-sha256", "0" * 64,
                "--validation-control-sha256", "0" * 64,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("--validation-verifier-sha256", result.stdout + result.stderr)

    def test_validation_control_rejects_governed_prompt_byte_mutation(self):
        with tempfile.TemporaryDirectory() as scratch:
            scratch_path = Path(scratch)
            target = scratch_path / "kit"
            shutil.copytree(ROOT, target)
            private_key, issuer_key_id, registry_path, registry_hash = self.create_external_test_registry(scratch_path)
            prompt_rows = [
                {"path": path.relative_to(target).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for path in sorted((target / "prompts").glob("*.prompt.md"))
            ]
            control_path = target / "config" / "validation-gates.json"
            control = json.loads(control_path.read_text(encoding="utf-8"))
            control["promptFiles"] = prompt_rows
            self.reseal_validation_control(control, private_key, issuer_key_id)
            control_path.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            prompt_path = target / prompt_rows[0]["path"]
            prompt_path.write_bytes(prompt_path.read_bytes() + b"\nsecurity-line-byte-mutation\n")
            control_hash = hashlib.sha256(control_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "prompt file"):
                VALIDATOR.load_verified_control(
                    target,
                    issuer_registry_path=registry_path,
                    expected_registry_sha256=registry_hash,
                    expected_control_sha256=control_hash,
                    require_external=True,
                )

    def test_model_execution_hashes_are_grounded_in_package_inputs(self):
        validation = VALIDATOR.Validation()
        VALIDATOR.validate_execution_receipts(validation)
        self.assertFalse(any("parameter input" in error.lower() or "redacted input" in error.lower() for error in validation.errors), validation.errors)
        self.assertTrue((ROOT / "examples" / "model-parameters.json").is_file())
        self.assertTrue((ROOT / "examples" / "model-redacted-input.json").is_file())

    def test_profile_statistics_reject_unrelated_business_scenario_evidence(self):
        def substitute(document):
            field = document["assets"][0]["fields"][0]
            field["statistics"]["sampleEvidenceRef"] = "99999999-9999-4999-8999-999999999999"
            field["evidenceRefs"] = ["99999999-9999-4999-8999-999999999999"]

        validation = self.run_against_mutated_package(
            {"examples/profile-manifest.json": substitute},
            VALIDATOR.validate_example_references,
        )
        self.assertTrue(any("statistics evidence" in error.lower() for error in validation.errors), validation.errors)

    def test_usage_proven_requires_independently_signed_usage_proof(self):
        import rfc8785

        def promote(document):
            record = document["records"][0]
            record["maturity"] = "usage-proven"
            record["usageProof"] = {
                "proofArtifactRef": "artifact://usage-proof/nonexistent.json",
                "proofArtifactSha256": "a" * 64,
                "issuerRegistrySha256": "b" * 64,
            }
            record["recordHash"] = hashlib.sha256(rfc8785.dumps({key: value for key, value in record.items() if key != "recordHash"})).hexdigest()

        validation = self.run_against_mutated_package(
            {"examples/evidence-bundle.json": promote},
            VALIDATOR.validate_evidence_integrity,
        )
        self.assertTrue(any("cannot be resolved and authenticated" in error.lower() for error in validation.errors), validation.errors)
        self.assertFalse(any("lacks" in error.lower() for error in validation.errors), validation.errors)

    def test_publication_cannot_claim_committed_without_storage_receipt(self):
        def claim(document):
            document["pointerTransition"]["committed"] = True

        validation = self.run_against_mutated_package(
            {"examples/publication-receipt.json": claim},
            VALIDATOR.validate_projection_seal,
        )
        self.assertTrue(any("storage transition receipt" in error.lower() for error in validation.errors), validation.errors)

    def test_execution_budget_allows_repeated_scope_but_rejects_duplicates_and_aggregate_overage(self):
        import rfc8785

        def add_second(document, operation_id="model:second", usage=100):
            second = copy.deepcopy(next(row for row in document["records"] if row["scope"] == "model-call"))
            second.update(operationId=operation_id, usage=usage, startedAt="2026-01-01T00:05:03Z", completedAt="2026-01-01T00:05:04Z")
            document["records"].append(second)
            document["contentHash"] = hashlib.sha256(rfc8785.dumps({key: value for key, value in document.items() if key != "contentHash"})).hexdigest()

        positive = self.run_against_mutated_package(
            {"examples/execution-budget-bundle.json": add_second},
            VALIDATOR.validate_execution_receipts,
        )
        self.assertEqual([], positive.errors)
        for name, operation_id, usage, expected in (
            ("duplicate", "50000000-0000-4000-8000-000000000001", 100, "duplicate operation"),
            ("aggregate", "model:second", 3000, "aggregate usage"),
        ):
            with self.subTest(name=name):
                validation = self.run_against_mutated_package(
                    {"examples/execution-budget-bundle.json": lambda document, operation_id=operation_id, usage=usage: add_second(document, operation_id, usage)},
                    VALIDATOR.validate_execution_receipts,
                )
                self.assertTrue(any(expected in error.lower() for error in validation.errors), validation.errors)

    def test_validation_artifact_size_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            oversized = target / "examples" / "oversized.json"
            with oversized.open("wb") as stream:
                stream.truncate(20 * 1024 * 1024)
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                self.assertIsNone(VALIDATOR.load_json("examples/oversized.json", validation))
            finally:
                VALIDATOR.ROOT = original_root
        self.assertTrue(any("maximum validation artifact bytes" in error.lower() for error in validation.errors), validation.errors)

    def test_prompt_contract_bounds_reject_asset_explosion_and_unbounded_purpose(self):
        schema = self.load("contracts/prompt-contracts.schema.json")
        evidence_pack = {
            "sourceId": "11111111-1111-4111-8111-111111111111",
            "sourceVersion": "v1",
            "policyHash": "b" * 64,
            "authorizationScopeId": "scope",
            "evidenceSetHash": "c" * 64,
            "assets": [{}] * 100001,
            "validatedRelationships": [],
            "evidenceIds": ["22222222-2222-4222-8222-222222222222"],
        }
        output = self.load("examples/prompt-output-semantic-asset.json") if (ROOT / "examples" / "prompt-output-semantic-asset.json").is_file() else {
            "assetId": "asset", "purpose": "x" * 100001, "purposeEvidenceIds": [], "domainCandidates": [], "assetRoleCandidates": [], "fieldSemantics": [], "identityHypotheses": [], "identityUnavailableReason": "unknown", "grainHypotheses": [], "freshnessBehavior": "unknown", "lineageHints": [], "qualityConcerns": [], "aliases": [], "confidence": 0,
        }
        input_errors: list[str] = []
        output_errors: list[str] = []
        VALIDATOR.validate_schema(evidence_pack, schema["$defs"]["businessModelEvidencePack"], schema, "$", input_errors, ROOT / "contracts" / "prompt-contracts.schema.json")
        VALIDATOR.validate_schema(output, schema["$defs"]["semanticAssetHypothesis"], schema, "$", output_errors, ROOT / "contracts" / "prompt-contracts.schema.json")
        self.assertTrue(input_errors)
        self.assertTrue(output_errors)

    def test_active_deletion_inventory_rejects_unresolved_artifact_page(self):
        def externalize(document):
            document["pages"][0]["pageUri"] = "artifact://immutable/page-1"

        validation = self.run_against_mutated_package(
            {"examples/deletion-inventory-active.json": externalize},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("artifact page" in error.lower() and "resolver" in error.lower() for error in validation.errors), validation.errors)

    def test_active_deletion_inventory_rejects_oversized_referenced_page_before_read(self):
        with tempfile.TemporaryDirectory() as scratch:
            target = Path(scratch) / "kit"
            shutil.copytree(ROOT, target)
            page_path = target / "examples" / "deletion-inventory-page-0001.json"
            with page_path.open("wb") as stream:
                stream.truncate(17 * 1024 * 1024)
            original_root = VALIDATOR.ROOT
            VALIDATOR.ROOT = target
            try:
                validation = VALIDATOR.Validation()
                VALIDATOR.validate_lifecycle_inventory(validation)
            finally:
                VALIDATOR.ROOT = original_root
        self.assertTrue(any("lifecycle inventory page exceeds maximum validation artifact bytes" in error.lower() for error in validation.errors), validation.errors)

    def test_active_deletion_inventory_rejects_policy_global_entry_count(self):
        import rfc8785

        def exceed(document):
            document["artifactCount"] = 10001
            document["contentHash"] = hashlib.sha256(rfc8785.dumps({key: value for key, value in document.items() if key != "contentHash"})).hexdigest()

        validation = self.run_against_mutated_package(
            {"examples/deletion-inventory-active.json": exceed},
            VALIDATOR.validate_lifecycle_inventory,
        )
        self.assertTrue(any("maximumdeletioninventoryentries" in error.lower() for error in validation.errors), validation.errors)


if __name__ == "__main__":
    unittest.main()