# Product and System Requirements

## Personas

| Persona | Goal |
|---|---|
| Source owner | Register a source and understand whether it was profiled correctly |
| Data steward | Review business meaning, policy classifications, quality, and conflicts |
| Agent builder | Retrieve compact, grounded context and supported capabilities |
| Analyst agent | Plan and execute read-only analysis without guessing schema or joins |
| Platform operator | Control cost, throughput, failure recovery, and evidence freshness |
| Auditor | Reconstruct what was read, inferred, validated, published, and used |

## Product Requirements

The authoritative machine-readable catalog is in `requirements/catalog.json`. This document groups the same requirements by product concern.

### Source onboarding and control

- **FR-001 Connector capability negotiation**: A source is registered through a neutral descriptor. The connector declares which operations it supports; its implementation version and canonical capability hash are pinned. Unsupported stages are explicit.
- **FR-002 Read-only enforcement**: Profiling uses allowlisted read operations. A future write plane must be a separate capability and authorization boundary.
- **FR-003 Durable run state machine**: Runs and stages have durable status, attempts, checkpoints, counts, leases, reasons, terminal outcomes, and typed terminal receipts that reconcile to the ledger.
- **FR-004 Stable source version**: Version identity is derived from stable structure and connector identity. Volatile counts and timestamps do not change structural versions.

### Structural and statistical profiling

- **FR-005 Deterministic sampling receipt**: Every approximation identifies population, actual work, method, seed or bucket, exactness, and error bounds.
- **FR-006 Statistical profile**: Source-appropriate profiling covers missingness, distinctness, distributions, formats, entropy, variants, temporal behavior, and outliers; every family has an explicit passed, failed, unavailable, or not-applicable outcome with sample evidence.
- **FR-007 Evidence envelope**: All outputs use one provenance-rich, append-only evidence contract.

### Semantics, identities, and relationships

- **FR-008 Semantic extraction**: Bounded evidence packs produce structured semantic hypotheses with strict validation.
- **FR-009 Deterministic semantic fallback**: Recoverable structured facts can be synthesized from generated text only when every referenced field resolves to harvested structure.
- **FR-010 Identity and grain distinction**: Scope, local identity, row version, content identity, and grain are separate concepts and separate validation claims.
- **FR-011 Broad relationship hypothesis generation**: Candidates may come from many independent signals, but blind all-pairs matching is forbidden.
- **FR-012 Relationship validation**: Query-ready relationships require authoritative or empirical support, and every published predicate, normalization, cardinality, coverage, operation, confidence, and validation-plan field is derived from that evidence.
- **FR-013 Sparse and high-cardinality validation**: Validation plans must avoid known sampling blind spots.
- **FR-014 Candidate scheduling**: Evidence-backed candidates are handled inline; remaining work is durable and resumable.
- **FR-015 Trusted graph paths**: Indirect paths use trusted direct edges and remain explicitly inferred.

### Quality and business meaning

- **FR-016 Quality model**: Quality dimensions retain their true granularity and distinguish failed, unavailable, and not-applicable checks.
- **FR-017 Business model extraction**: The system derives candidate domains, entities, events, measures, dimensions, metrics, processes, states, scenarios, glossary terms, and model patterns using typed expressions and resolvable evidence references.
- **FR-018 Usage learning**: Repeated successful and failed usage adjusts ranking and revalidation while preserving privacy and validation gates.

### Agent products

- **FR-019 Immutable profile manifest**: A source-version-scoped structural and business projection is available to tools and agents.
- **FR-020 Capability manifest**: Supported questions, required assets and relationships, metrics, result shapes, constraints, and warnings are published separately.
- **FR-021 Hybrid intelligence retrieval**: Retrieval combines lexical, semantic, graph, temporal, and faceted signals after policy and version gates and returns the complete sealed projection coordinate with independently reconciled section counts.

### Governance and extension

- **FR-022 Privacy classification before semantics**: Redaction and policy classification happen before model calls and index publication.
- **FR-023 Untrusted-content boundary**: Source content is never instruction or configuration.
- **FR-024 Evidence feedback lifecycle**: Reviews add evidence rather than mutating history.
- **FR-025 Source-specific profiling**: Adapters can extend structure and validation through built-in closed payload kinds or immutable allowlisted extension schemas while preserving common evidence, replay-resistant signed redaction, and manifest-coordinate contracts.
- **FR-026 Source consistency boundary**: Every run binds observations to a snapshot, transaction, watermark/offset range, ETag set, or explicit before/after consistency check.
- **FR-027 Authenticated agent execution journey**: The API covers capability inspection, retrieval, typed plan validation/execution, evidence lookup, cancellation, feedback, revocation, deletion, and receipts; absent and inaccessible protected identifiers are indistinguishable.
- **FR-028 Isolated untrusted-content parsing**: Documents, archives, and media decode only in credential-free, network-isolated, resource-bounded workers that emit receipts.
- **FR-029 Model admission and cache governance**: Semantic model use is deny-by-default, admitted before execution against a versioned residency policy, and every cache entry is bound to provider and deployment identity as well as that decision.
- **FR-030 Secure source registration boundary**: Whole-request secret scanning—including named assignments, token families, and high-entropy opaque values—plus opaque credential identifiers and canonical relative locators precedes any network access.
- **FR-031 Immutable projection coordinate**: Structural source version and projection manifest version are distinct; connector ID/version/capability hash, scope, policy, taxonomy, pipeline, methods, evidence cutoff, and revocation epoch are pinned everywhere.
- **FR-032 Tamper-evident audit chain**: Audit digests cover the event body and predecessor link; authorization decisions agree with outcomes and grants, and action receipts resolve to matching events.
- **FR-033 Scope containment in served projections**: A manifest describes only its own scope, and cross-scope relationships require a derived-and-granted authorization receipt.
- **FR-034 Data handling in served projections**: Manifest assets and fields carry their own handling record, and published statistics are aggregate-only.
- **FR-035 Bounded, provenance-marked agent responses**: Free text is length-bounded and provenance-marked; omissions reconcile to a closed section vocabulary, and caveats/conflicts cite coordinate-compatible evidence.
- **FR-036 Policy-bound sandbox limits and single-writer fencing**: Parser ceilings come from policy, and every evidence write carries the writing run's fencing token.

## Non-Functional Requirements

### NFR-001 Fail-closed validation

A gate is invalid when nothing ran. Counts must distinguish expected, attempted, completed, failed, skipped, not run, and unavailable. A process exit code without those counts is not sufficient evidence. The package validator dispatches its declared gate registry at runtime and records an ordered per-gate receipt; source-code reachability inspection is not accepted as proof of execution.

### NFR-002 Observability

Every run emits correlated telemetry for:

- Run and stage lifecycle.
- Connector calls and retries.
- Bytes, rows, objects, and content units read.
- Sampling method and actual work.
- Semantic calls, cache hits, tokens, latency, parse retries, and failures.
- Relationship candidates, gates, validators, outcomes, and fallbacks.
- Evidence writes and projection builds.
- Retrieval filters, ranks, omissions, and token budgets.

Silent catches are prohibited for a signal that affects evidence quality.

### NFR-003 Bounded resource use

All work has wall-clock, byte, row, object, query, model-token, concurrency, traversal, and output budgets. Exhaustion produces an explicit partial result with coverage, not a fabricated complete result.

### NFR-004 Idempotent evolution

Metadata stores evolve additively. Existing stores must receive new fields without destructive recreation. Repeated writes are safe; readers select current evidence by stable logical key and source version.

### NFR-005 Benchmark-governed tuning

No threshold or algorithm is accepted because one run looks better. A fixed corpus contains:

- Exact positive and exact negative relationships.
- Sparse and highly skewed fields.
- High-cardinality key spaces.
- Scoped and versioned identities.
- Homonyms and semantic aliases.
- Mixed types and nested variants.
- Empty, all-null, inaccessible, and unsupported sources.
- Prompt-injection and sensitive-content cases.

Every change reports precision, recall, coverage, calibration, latency, source work, and model use.

### NFR-006 Deletion and revocation propagation

Derived evidence, vectors, indexes, caches, and manifests obey source deletion, entitlement revocation, and policy change within a measurable objective.

### NFR-007 Calibration and honesty

Confidence is calibrated separately for each evidence class. It never replaces maturity, outcome, coverage, or caveats. A high-confidence hypothesis is still a hypothesis.

## Business Rules

| ID | Rule |
|---|---|
| BR-001 | No source is discoverable or retrievable before authorization is resolved. |
| BR-002 | A source that is still profiling is visible as incomplete but excluded from capabilities requiring missing stages. |
| BR-003 | Reprofiling creates a new immutable run; it never rewinds a terminal run. |
| BR-004 | One source version and one policy version bind every evidence record and manifest. |
| BR-005 | Missing optional evidence lowers coverage; missing required evidence withholds the dependent capability. |
| BR-006 | Validation failure and validation unavailability are different outcomes. |
| BR-007 | A generated relationship required by a business scenario remains provisional until validated. |
| BR-008 | A direct relationship and an inferred multi-hop path are never represented as the same maturity. |
| BR-009 | Entity identity excludes row-version fields; row grain may include them. |
| BR-010 | Scope fields cannot be discarded when collisions exist across scopes. |
| BR-011 | Sensitive values do not appear in prompts, embeddings, examples, manifests, or logs by default. |
| BR-012 | Top values are positive discovery evidence but weak negative evidence for high-cardinality fields. |
| BR-013 | Historical reads require an explicit source version and never fall back to current. |
| BR-014 | An earlier evidence record is superseded by a later one, never overwritten. |
| BR-015 | Human review may promote maturity only under a named review policy and with the reviewed version recorded. |
| BR-016 | Repeated successful usage influences ranking but cannot validate a new source version by itself. |
| BR-017 | Every manifest truncation or cap is reported in its coverage receipt. |
| BR-018 | A source adapter may add source-specific evidence kinds but cannot weaken common safety invariants. |
| BR-019 | A terminal stage receipt must resolve by typed identifier, carry the full run-stable coordinate, cite dependency receipts, bind output artifact bytes, be signed, and exactly reconcile its stage attempt, outcome, method, timestamp, and work counts. |
| BR-020 | Inaccessible and absent protected identifiers return the same fixed resource-unavailable response without request-derived detail. |
| BR-021 | Retrieval caveats and both sides of conflicts require resolvable evidence under the served projection coordinate. |
| BR-022 | A read plan contains exactly one typed operation until operation-attributed heterogeneous result contracts are available. |
| BR-023 | Run-level asset, field, and relationship coverage reconciles exactly; aggregate summaries cannot contradict stage receipts. |
| BR-024 | Every acceptance criterion has a stable ID and at least one explicit, resolvable BDD mapping; list cardinality is not traceability. |

## Non-Goals and Anti-Requirements

- Do not hardcode business tables, fields, domains, metrics, or source names in generic algorithms.
- Do not accept generated descriptions, labels, joins, metrics, or scenarios as facts.
- Do not use a single random sample as proof of absence.
- Do not independently sample both sides of a very large key relationship and infer no overlap.
- Do not derive global identity from a local identifier when scope exists.
- Do not let unvalidated edges seed transitive graph expansion.
- Do not treat stage completion as proof that manifests and agent retrieval were refreshed.
- Do not use cache age alone to decide whether a projection matches source evidence.
- Do not catch and ignore failures that lower evidence quality.
- Do not publish raw profile stores directly as an agent prompt.
- Do not return a default confidence, metric, relationship, or business meaning solely to keep a contract non-empty.

## Definition of Done

A production implementation is done only when:

1. All P0 requirements trace to executable tests.
2. The benchmark corpus passes positive and negative controls.
3. At least one real source of each claimed source kind has been exercised end to end.
4. Run recovery is proven by terminating and resuming a live run.
5. Deletion and entitlement revocation are proven across all derived stores.
6. Profiling telemetry has been used to find and fix at least one issue.
7. The profile and capability manifests are consumed by an agent in a real task.
8. That agent cites evidence and refuses at least one unsupported question.
9. Load and stress targets are met with no silent missing work.
10. Security, privacy, and prompt-injection reviews pass.
