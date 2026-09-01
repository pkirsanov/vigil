# Implementation Roadmap

## Delivery Strategy

Build vertically, contract first. Each milestone must take a source from registration to an agent-consumable artifact and prove both positive and negative behavior. Avoid building every profiler before the evidence and consumption loop works.

## Milestone 0: Contracts and Harness

### Deliver

- Adopt source, evidence, run, profile-manifest, capability-manifest, and API contracts.
- Establish requirement-to-BDD traceability.
- Build fixture source adapter and in-memory test evidence store.
- Run the package validator in continuous integration.
- Establish benchmark corpus and baseline report.

### Exit gate

- All schemas parse.
- Examples validate.
- Every P0 requirement has BDD coverage.
- Zero-work mutation fails.

## Milestone 1: One Structured Source, End to End

### Deliver

- Connector capability negotiation and typed read plans.
- Durable source registry, run state, leases, queue, and checkpoints.
- Structural discovery and stable source version.
- Deterministic field statistics with receipts.
- Evidence ledger.
- Minimal profile manifest.
- Lexical/faceted retrieval and evidence citations.

### Exit gate

- New source reaches a published manifest without manual documentation.
- Restart during profiling resumes without duplicate logical evidence.
- Empty, all-null, inaccessible, and unsupported fixtures produce distinct outcomes.
- Source deletion removes current projections.

## Milestone 2: Semantics, Identity, and Quality

### Deliver

- Privacy classification/redaction before semantics.
- Strict semantic extraction and deterministic fallback.
- Identity/grain candidates and exact/bounded validators.
- Quality and freshness evidence at explicit granularity.
- Vector index and hybrid retrieval.
- Review/feedback evidence.

### Exit gate

- Scoped and versioned identity benchmark cases pass.
- Invented paths are rejected.
- Secrets never enter prompts or indexes.
- Confidence calibration report exists.

## Milestone 3: Relationships and Graph

### Deliver

- Multi-signal candidate generation and deduplication.
- Evidence-based inline gate.
- Durable deferred queue.
- Adaptive relationship validation plans.
- Trusted graph paths.
- Per-asset relationship coverage.
- Relationship review and time-bounded suppression.

### Exit gate

- Positive/negative, sparse, skewed, composite, scoped, and high-cardinality benchmark cases meet precision/recall targets.
- Restart preserves deferred work.
- Ungated-transitive mutation fails.
- No placeholder coverage or path cost reaches manifests.

## Milestone 4: Business Model and Capabilities

### Deliver

- Asset roles and storage/model patterns.
- Domains, entities, events, processes, measures, dimensions, metrics, scenarios, and glossary.
- Metric parser/type checker/dry-run validation.
- Scenario relationship closed loop.
- Capability manifest.
- Agent planning and unsupported-question refusal.

### Exit gate

- Every business concept and capability cites evidence.
- Capabilities with unvalidated dependencies are withheld.
- Agent uses manifests on a real task and correctly refuses an unsupported task.

## Milestone 5: Usage and Lineage Learning

### Deliver

- Native lineage and reusable transformation analysis.
- Privacy-safe usage pattern normalization and fingerprints.
- Usage-proven maturity and drift events.
- Targeted revalidation and reprofile triggers.
- Retrieval ranking informed by repeated successful use.

### Exit gate

- Raw caller identity and query literals are absent from learned patterns.
- One miss cannot permanently suppress a relationship.
- New usage relationship triggers targeted validation.

## Milestone 6: Universal Source Expansion

Add source kinds in this order because they reuse the most existing machinery:

1. Tabular files.
2. Nested/semi-structured records.
3. APIs from contracts and sampled responses.
4. Event streams.
5. Document corpora.
6. Property graphs.
7. Multimodal collections.

For each source kind:

- Add connector capability profile.
- Add source-specific structure and sampling.
- Add validators.
- Map output to common evidence and manifests.
- Add benchmark fixtures and adversarial cases.
- Prove deletion and entitlement propagation.

## Recommended Module Boundaries

```text
contracts
connector-sdk
control-plane
orchestrator
policy-gateway
profilers-common
profilers-tabular
profilers-nested
profilers-documents
profilers-streams
profilers-graphs
profilers-media
semantic-workers
identity-validation
relationship-intelligence
quality-and-anomaly
business-model
evidence-ledger
projection-builder
index-builders
retrieval-api
review-api
evaluation-harness
```

## Build-vs-Buy Boundary

Do not couple the contracts to a specific:

- Scheduler or queue.
- Relational/analytical/document store.
- Vector database.
- Search engine.
- Graph database.
- Language or embedding model.
- Query language.
- Deployment platform.

Select products behind interfaces based on source locality, scale, access control, latency, and operational maturity.

## Migration from an Existing Profiler

1. Inventory current output tables and APIs.
2. Map each field to evidence kind, maturity, outcome, source version, and sample receipt.
3. Stop treating generated semantics and raw joins as validated.
4. Add stable logical keys and read-side current selection.
5. Introduce immutable profile manifest over existing evidence.
6. Add capability manifest and retrieval.
7. Add missing validation states and coverage.
8. Replace in-memory work with durable queue/leases.
9. Add privacy classification before model/index paths.
10. Add benchmarks and mutation tests before tuning.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Candidate explosion | Concrete-signal requirement, ranking, inline gate, durable deferred queue |
| False relationships | Source validation, scope/grain model, homonym detection, trusted paths |
| Sampling blind spots | Deterministic/stratified plans, sparse/high-cardinality fallbacks, receipts |
| Generated hallucination | Strict schemas, path membership validation, deterministic fallback, inferred maturity |
| Sensitive-data leakage | Pre-semantic classification, redaction, scoped indexes, deletion propagation |
| Stale intelligence | Source/evidence/model/policy versions, dependency invalidation, atomic publication |
| Misleading completeness | Explicit denominators and failed/unavailable/not-run counts |
| High cost | Stage budgets, caching by evidence, batching, source-side aggregates, foreground reservation |
| Vendor lock-in | Connector/model/store interfaces and portable contracts |
| Silent degradation | Failure evidence, coverage regression alerts, consumption probes |

## Engineering Rules

- Begin each behavior with a failing Given/When/Then test.
- Capture raw red and green evidence.
- Test process behavior through the same invocation used in production.
- Mutation-test gates, fallbacks, and “must not” rules.
- Run validators against a healthy real corpus before trusting them.
- Verify writes through a different read path.
- Never call a stage complete from an exit code alone.
- Keep source-specific terms out of common modules.
