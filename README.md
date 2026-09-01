# Agent Data Profiler Kit

## Purpose

This package specifies a technology-neutral system that can be pointed at an authorized data source, profile it, mature observations into validated evidence, and publish compact intelligence products for autonomous consumers.

The package supports:

- Structured tables and files.
- Nested and semi-structured records.
- Documents and free text.
- Application programming interfaces.
- Event streams.
- Property graphs.
- Images, audio, video, and mixed-media collections.

The goal is not merely to catalog fields. The goal is to make a source safely usable by an agent: discoverable, statistically characterized, semantically described, related, ranked, indexed, policy-tagged, versioned, and honest about uncertainty.

## Core Rule

**Profile output is evidence, not truth.** A name, statistical pattern, embedding match, generated description, or business scenario remains a hypothesis until an appropriate validator confirms it. Every claim carries status, provenance, confidence, scope, freshness, and supporting or contradicting evidence.

## Package Contents

| Area | Contents |
|---|---|
| Product | Vision, business outcomes, requirements, non-goals, and acceptance gates |
| Architecture | Source adapters, orchestration, evidence store, semantic graph, indexes, manifests, and agent retrieval |
| Algorithms | Sampling, statistics, identity/grain inference, relationship discovery, quality, drift, ranking, and business-model extraction |
| Contracts | JSON Schemas for sources, typed logical evidence, signed stage outputs, statistical/business/join projections, audit events, model/cache provenance, single-operation typed plans/results, agent-response policy, signed projection-safety and artifact-level lifecycle receipts, benchmark corpus/comparison, registry-backed extensions, and an OpenAPI surface |
| Configuration | A reference policy plus independent gate, protected-operation, test-floor, and extension-schema registries |
| Taxonomies | Source kinds, evidence maturity, semantic roles, relationship kinds, and outcome states |
| Pipeline | Canonical stages with dependency and publication semantics, the capability negotiation matrix, and per-source-kind execution profiles |
| Prompts | Strict templates for semantic extraction, business-model synthesis, relationship adjudication, and document analysis |
| BDD | Executable-style Given/When/Then behavior specifications across source types and failure modes |
| Examples | Sanitized registration, source, run, typed stage receipts, evidence, signed extension, retrieval, manifest, plan, audit, model, and parser records |
| Security | Adversarial registration fixtures for labeled secrets, credential token families, high-entropy values, benign controls, and endpoint escapes |
| Validation | A fail-closed package validator, benchmark scorer, and test runner that enforce 32 exact runtime gates, a signed test-file inventory and positive discovery floor, criterion-level BDD traceability, schemas/OpenAPI, byte/hash/signature chains, coordinates, cross-contract references, links, examples, and BDD completeness |

## Reading Order

1. [Executive overview](docs/00-executive-overview.md)
2. [Product and system requirements](docs/01-product-requirements.md)
3. [Reference architecture](docs/02-reference-architecture.md)
4. [Pipeline and algorithms](docs/03-pipeline-and-algorithms.md)
5. [Evidence and business model](docs/04-evidence-and-business-model.md)
6. [Agent consumption](docs/05-agent-consumption.md)
7. [Lessons, gotchas, and tuning](docs/06-lessons-gotchas-and-tuning.md)
8. [Security, governance, and privacy](docs/07-security-governance-and-privacy.md)
9. [Operations, observability, and service objectives](docs/08-operations-observability-and-slos.md)
10. [Implementation roadmap](docs/09-implementation-roadmap.md)
11. [Evaluation and acceptance](docs/10-evaluation-and-acceptance.md)

The machine-readable source of truth for requirements is [requirements/catalog.json](requirements/catalog.json). The reference policy is [config/reference-policy.yaml](config/reference-policy.yaml).

## Adoption Modes

### Design-only

Use the requirements, architecture, evidence model, and BDD files to design a new implementation.

### Contract-first

Adopt the JSON Schemas and API contract first. Implement connectors and stages behind those stable boundaries.

### Incremental retrofit

Map an existing profiler's artifacts to the evidence envelope, add explicit maturity states, then add manifests and agent retrieval without replacing the underlying store immediately.

### Evaluation harness

Use the BDD suite, mutation catalog, and benchmark plan as an independent acceptance harness for an existing implementation.

## Quick Validation

Install the pinned validation dependencies, then run the structural/contract validator and its mutation-oriented self-tests:

```text
python -m pip install -r requirements-validation.txt
python -B scripts/validate_package.py
python -B scripts/run_tests.py
```

Those commands run in **conformance mode**. Package-local public keys verify only that the generic examples, hashes, and signatures agree. They are not production trust anchors. Production verification requires a registry outside the package and an independently supplied SHA-256 pin over its exact bytes:

```text
python -B scripts/validate_package.py --trust-mode production --trust-registry <external-registry.json> --trust-registry-sha256 <registry-sha256> --validation-control-sha256 <control-sha256> --validation-verifier-sha256 <validation-control-py-sha256>
python -B scripts/run_tests.py --trust-mode production --trust-registry <external-registry.json> --trust-registry-sha256 <registry-sha256> --validation-control-sha256 <control-sha256> --validation-verifier-sha256 <validation-control-py-sha256>
```

The external registry declares `registryUse: production`. Every production issuer is authorized for exactly one purpose, no key is reused across purposes, and private signing material is never stored or derivable in this package. The independently supplied control-byte pin prevents replay of an older still-valid signed validation control; the issuer-registry pin alone does not provide rollback protection. The verifier-byte pin is checked by each entrypoint with Python standard-library hashing before `scripts/validation_control.py` is loaded or imported, so replacement of the verifier cannot bypass the registry, control, or test-file checks while the original verifier pin remains in force. Mutation tests generate ephemeral keys in memory and place only temporary public registries outside copied packages.

### Production bootstrap root of trust

The verifier pin is not proof of entrypoint self-integrity. No Python file can defend against replacement of itself: an attacker who replaces `scripts/run_tests.py` or `scripts/validate_package.py` can remove its precheck. A real deployment therefore MUST use an immutable launcher, policy engine, signed image, or equivalent external caller that independently pins the exact entrypoint bytes and supplies the registry, validation-control, and validation-verifier pins. Those launcher and pin bytes must live outside the package's writable trust domain. This external entrypoint pin is the deployment root of trust; package validation does not and cannot prove it.

All package receipts and payloads are **conformance fixtures**, not production observations. In particular, the publication example carries a signer-attested pointer transition; it does not claim an independently verified storage commit. A production `committed` claim requires a separate storage-authority receipt binding the precondition ETag/revision, committed revision, store identity, transaction ID, and immutable readback. `usage-proven` evidence similarly requires a pinned `artifact://` usage-proof artifact and independently pinned issuer registry; because this package has no runtime resolver or independent usage corpus, static validation always rejects that maturity. Likewise, active `artifact://` deletion pages fail closed unless the runtime supplies an explicit immutable resolver and independent byte pin. Active deletion conformance is capped by policy at 10,000 total entries, 1,000 entries per page, and the validation artifact byte ceiling before a page is read; the larger 100,001-entry example remains schema-only. The static package does not prove those runtime authority boundaries.

All identity-shaped values are synthetic conformance data. No fixture identifier refers to a real person, organization, account, tenant, host, or deployed resource. Patterned UUIDs, UUIDv5-shaped redaction receipt IDs, trace IDs, signatures, and hashes exist only to exercise contract and tamper-evidence behavior. The caller hash re-derives from `example-tenant`, `example-agent`, and `conformance-only-subject-salt-v1`; email and URL examples use the reserved `.invalid` domain. Credential-shaped strings and loopback or link-local addresses appear only in rejection fixtures. Real names, company or product names, operational domains, user-profile paths, and deployed-resource identifiers are prohibited.

The validator is fail-closed and prints only a final `PASS` or `FAIL` verdict plus actionable failures. It runtime-dispatches every declared gate, reconciles the list to an independent expected-gate manifest, records each gate's executed-check delta, and rejects missing, duplicate, exceptional, or zero-check gates. The test runner fails below its independently signed test floor, on skipped or expected-failure outcomes, or when executed/discovered counts differ. A zero-scenario, zero-requirement, or zero-benchmark-case run is invalid, never a pass. Criterion mappings are bound to acceptance text, scenario reference, and parsed Gherkin outcome steps by a canonical hash also pinned in the signed control, so changing a mapping and copying its tag is detected. The executable benchmark fixture includes all required slices and all seven before/after measures, but is explicitly illustrative rather than runtime performance evidence. The verdict is **package structural and contract validation**, not proof that a future runtime implementation satisfies the behavioral specifications. Runtime acceptance requires binding the BDD specifications and benchmark contracts to real implementation step definitions, fixtures, and raw run evidence.

## Design Commitments

1. Read-only by default; writes require a separate explicit capability.
2. Content is untrusted data, never executable instruction.
3. Credentials are referenced, never embedded.
4. Raw sensitive values are excluded from manifests and model prompts by default.
5. Observation, inference, validation, curation, and usage proof are different maturity states.
6. Confidence never substitutes for validation status.
7. Empty, not applicable, not run, unavailable, rejected, and successful-with-zero-findings are distinct outcomes.
8. Every approximation records population, sample, method, error bounds, and actual rows inspected.
9. Relationships are query-ready only after source-appropriate validation.
10. Manifests are immutable, version-scoped projections assembled from evidence, not mutable truth documents. Structural `sourceVersion`, projection `manifestVersion`, and connector ID/version/capability hash are distinct pinned coordinates.
11. Agent retrieval applies entitlement before candidate generation and returns citations, caveats, and counter-evidence.
12. Tuning changes are accepted only against a fixed benchmark corpus with before/after evidence.
13. Untrusted documents and media are decoded only in credential-free, network-isolated, resource-bounded workers.
14. Semantic model use is deny-by-default and admitted against data classification, residency, retention, and training-use rules before invocation.
15. Every terminal stage has a signed receipt that resolves dependency receipts and exact output artifact bytes.
16. Every acceptance criterion maps explicitly to one or more resolvable BDD scenarios.
17. Read plans contain one typed operation until operation-attributed heterogeneous results are defined.
18. Pending runs exist before lease acquisition; running runs expose an unexpired matching lease; resume requires a purpose-signed predecessor/checkpoint binding and a fresh fencing token.
19. Every index carries the complete projection coordinate, including manifest version, and hashes that coordinate into its namespace.
20. Every agent-facing manifest, retrieval, and typed-read response carries a conservative provenance/default policy plus finite serialized and text limits.
21. Publication is blocked without a purpose-signed projection-safety receipt derived from a salted source-value fingerprint set and exact served-manifest hashes.
22. Completed deletion requires a purpose-signed, artifact-level pre-deletion inventory; zero self-reported counts are not proof of enumeration.

## Non-Goals

- Copying an entire source into the profiler.
- Declaring generated semantics authoritative without validation.
- Executing arbitrary source content or generated queries without policy checks.
- Publishing raw samples as agent context.
- Hiding unsupported source capabilities behind default values.
- Replacing source-specific governance, authorization, or retention rules.

## Versioning

The package uses semantic versioning. Contract-breaking schema changes require a major version. Additive evidence kinds, index kinds, optional fields, BDD scenarios, and connector capabilities may be minor changes; the contracts accept any `1.x.y` taxonomy version so an additive taxonomy change does not invalidate previously written records. Corrections that preserve contracts are patch changes.
