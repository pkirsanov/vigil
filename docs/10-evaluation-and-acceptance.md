# Evaluation and Acceptance

## Evaluation Philosophy

The system must be tested as a chain from source to agent decision. A helper-level unit test proves a helper; it does not prove that the live pipeline invokes it, persists evidence, rebuilds projections, retrieves the result, or changes an agent plan.

## Test Pyramid

### Unit

- Canonicalization and version hashing.
- Sampling-plan selection and receipts.
- Statistical aggregation and edge cases.
- Strict semantic parsing and path membership.
- Identity/grain normalization.
- Candidate deduplication and rank.
- Validation-plan selection.
- Confidence and maturity state rules.
- Projection curation and coverage.
- Authorization/policy filters.

### Contract

- Connector SDK conformance.
- JSON Schema examples.
- API producer/consumer parity.
- Evidence round-trip through storage.
- Stage graph and run-state transitions.
- Index record and deletion contracts.

### Integration

- Real source emulator or disposable source.
- Durable queue, lease, fencing, and restart recovery.
- Semantic provider or deterministic test double only at external boundary.
- Evidence ledger, projection builder, and indexes.
- Retrieval with authorization and source version.

### End to end

- Register source.
- Interrupt and resume profiling.
- Publish manifests/indexes.
- Ask an agent a supported question.
- Validate and execute a typed read plan.
- Return a grounded answer with evidence.
- Ask an unsupported question and observe refusal.
- Revoke source and confirm derived data disappears.

### Stress and chaos

- Many assets and wide schemas.
- Candidate explosion.
- Large/high-cardinality/sparse/skewed sources.
- Semantic throttling and malformed output.
- Connector timeout and partial partitions.
- Queue restart and stale lease holder.
- Projection failure during publication.
- Concurrent retrieval while a new version builds.

## Golden Corpus

This reference package is **specification-only with respect to runtime benchmark results**. It includes an executable nine-case conformance corpus, complete seven-metric comparison record, schemas, and deterministic fail-closed scorer so the contract itself is reusable and mutation-testable. The included numbers are explicitly illustrative and are not measurements of an implementation. An adopting implementation must replace the generic cases with executable source fixtures, retain declared outcomes, run the scorer over raw per-case results, and preserve raw run artifacts before making any precision, recall, latency, cost, or reliability claim.

Every case declares:

- Source fixture and version.
- Policy and connector capabilities.
- Expected applicable stages.
- Expected evidence outcomes, including expected rejections.
- Expected profile and capability sections.
- Expected unsupported conclusions.
- Expected privacy redactions.
- Expected performance envelope.

The scorer judges agreement with declared outcomes. It does not equate success with exit code zero; many negative cases correctly expect rejection.

Run the reusable conformance scorer with:

```text
python -B scripts/evaluate_benchmark.py benchmark/corpus.json benchmark/comparison.json
```

The command must report all nine required slices, all seven before/after measures, and nonzero execution for every case. A missing case, metric, slice, skipped case, not-run case, outcome disagreement, correctness regression beyond policy, calibration regression beyond policy, or declared/derived decision mismatch is a failure.

### Scorer contract

For each case and repetition, the scorer emits:

- Case ID, corpus version, implementation version, policy hash, and method/model/prompt versions.
- Expected and observed outcome, applicable stages, evidence kinds, manifest sections, redactions, and unsupported conclusions.
- Per-metric numerator, denominator, value, and unavailable reason.
- Executed, not-run, failed, and skipped counts; zero executed is invalid.
- Slice labels and resource measurements.
- PASS or FAIL based on agreement with the case, not on process exit code alone.

Flake detection groups repetitions by case ID. Aggregate reports reconcile exactly to per-case rows and retain raw receipts. Missing cases, unresolved expected evidence, partial execution without an explicit expected partial outcome, or a scorer/schema version mismatch fail the benchmark.

## Core Metrics

### Structural

$$
Precision = \frac{correct\ discovered\ items}{all\ discovered\ items}
$$

$$
Recall = \frac{correct\ discovered\ items}{all\ expected\ items}
$$

Report by asset, field/path, type, and variant.

### Statistical

- Relative/absolute error.
- Confidence-interval coverage.
- Rare-value recall.
- Stratification coverage.
- Actual source work.

### Semantic

- Field-role macro/micro F1.
- Purpose/domain agreement.
- Invented-path rate.
- Strict parse success.
- Calibration error.

### Identity and relationships

- Candidate recall.
- Validated precision and recall.
- Scoped/versioned correctness.
- Composite predicate correctness.
- Per-asset partner coverage.
- Rejection correctness.
- Unavailable-vs-rejected confusion rate.
- Path precision.

### Business model

- Entity/event/process agreement.
- Measure unit/additivity/grain correctness.
- Metric execution and fixture-result agreement.
- Scenario usefulness and required-path closure.
- Evidence citation completeness.

### Retrieval and agents

- Recall at $k$, nDCG at $k$, mean reciprocal rank.
- Diversity and duplicate rate.
- Counter-evidence recall.
- Token efficiency.
- Plan schema validity.
- Read-plan validation pass.
- Execution success.
- Grounded-answer rate.
- Unsupported-question refusal rate.

## Calibration

For evidence with predicted confidence $p$, compare observed correctness by bins. Track expected calibration error:

$$
ECE = \sum_b \frac{|B_b|}{n} |acc(B_b) - conf(B_b)|
$$

Calibrate separately by evidence kind, method, source kind, and maturity. Do not calibrate generated semantic confidence together with relationship usefulness.

## Mutation Catalog

Every mutation must compile and execute the affected tests.

| Mutation | Required kill |
|---|---|
| Treat zero work as pass | Run-validation scenario fails |
| Remove source-version filter | Historical-manifest scenario fails |
| Admit inferred relationship as query-ready | Capability withholding scenario fails |
| Drop scope path from identity | Scoped-collision scenario fails |
| Drop version path from row grain | Versioned-grain scenario fails |
| Move sparse filter after random sample | Sparse-key scenario fails |
| Sample both high-cardinality relationship sides | High-cardinality scenario fails |
| Allow untrusted edge into path graph | Path-trust scenario fails |
| Ignore generated unknown field | Hallucinated-field scenario fails |
| Skip additive schema update when store exists | Schema-evolution scenario fails |
| Swallow quality-check failure | Degraded-quality scenario fails |
| Remove redaction before semantic call | Sensitive-sample scenario fails |
| Keep vectors after source deletion | Deletion-propagation scenario fails |
| Replace a typed stage receipt with an arbitrary string or wrong receipt type | Run-receipt reconciliation fails |
| Remove one declared gate from runtime dispatch or make it execute zero checks | Runtime gate execution receipt fails |
| Relabel a denied audit decision as successful or grant a permission | Audit authorization consistency fails |
| Add an undeclared omission section or remove caveat/conflict evidence | Retrieval contract or provenance gate fails |
| Change a signed extension payload, coordinate, asset, or evidence reference | Extension signature or binding gate fails |
| Return a distinct forbidden response for an existing protected resource | Protected-resource indistinguishability gate fails |
| Insert an unlabeled high-entropy credential-family value | Whole-request secret-scanner scenario fails |
| Remove one real gate from both code flow and a mutable list | Independent expected-gate manifest fails |
| Remove or undiscover every test | Fail-closed runner fails below the signed 155-test floor |
| Remove authorization from ranking hard gates | Policy semantic gate fails |
| Mark deletion complete while serving remains failed | Lifecycle schema and semantic gate fail |
| Move a trusted receipt before issuer activation or after expiry | Purpose-specific trust-window validation fails |
| Change connector implementation or capability hash under an existing projection | Connector-coordinate reconciliation fails |
| Change a stage output byte, dependency receipt, or output item count | Signed stage-ledger validation fails |
| Change provider or model deployment digest while retaining a cache key | Cache key/namespace derivation fails |
| Admit a model after execution or in an incompatible region | Model-admission chronology/residency gate fails |
| Publish empty field statistics or an unlabelled sampled distinct count | Statistical contract/semantic gate fails |
| Change published cardinality, normalization, operation, or coverage while retaining genuine join evidence | Relationship projection binding fails |
| Remove a business-concept/model-pattern vector or dangle its references | Business/model-pattern conformance gate fails |
| Replay an evidence or extension redaction signature across an asset, epoch, connector, or evidence set | Replay-resistant signature envelope fails |
| Substitute, omit, or duplicate an acceptance-to-scenario mapping | Criterion-level traceability gate fails |
| Represent a pending run as already owning a token, or a running run with an expired/mismatched lease | Run-lifecycle conformance fails |
| Resume from an unsigned, incompatible, expired, or dependency-incomplete checkpoint | Signed resume-checkpoint validation fails |
| Drop manifest version from an index coordinate or namespace | Projection seal fails |
| Request a source/manifest version other than the authorized projection or exceed deployment read ceilings | Read-plan validation fails |
| Place a direct identifier under an attacker-selected `*Id` field | Content-based served-value scan fails |
| Copy an ordinary source value into served prose | Purpose-signed source-fingerprint collision gate fails |
| Replace base64-only prompt input with inline JSON | Prompt transport contract fails |
| Mark deletion complete with zero enumeration or omit a published index | Signed artifact-level lifecycle reconciliation fails |
| Remove a before/after metric, difficult slice, case result, or hide a miss behind latency | Executable benchmark scorer fails |
| Replay a historically valid validation control without the independently governed current control-byte pin | Production trust initialization fails |

## Benchmark Acceptance Template

```text
Change:
Method/policy versions:
Corpus version:

Correctness before/after:
  structural precision/recall
  semantic F1/invented-path rate
  relationship precision/recall
  business-model agreement
  retrieval nDCG/grounded-answer rate

Resource before/after:
  wall time
  source units/bytes read
  model tokens/calls
  queue throughput
  manifest size

Difficult slices:
  sparse
  high-cardinality
  skewed
  scoped
  versioned
  homonym
  unstructured
  adversarial

Decision: PASS or FAIL
Rationale:
```

## Package Acceptance

The reusable package itself passes when:

- Every listed artifact exists.
- All JSON contracts and examples parse.
- Every example validates against its contract.
- Requirement IDs are unique.
- Every acceptance criterion has a stable ID and at least one explicit resolvable BDD mapping; duplicate mappings cannot inflate coverage.
- Every BDD feature has at least one scenario and every scenario has Given, When, and Then.
- Internal relative links resolve.
- Forbidden source-specific/vendor terms are absent.
- Placeholder markers are absent.
- The validator executes non-zero checks and returns `PASS`.
- Every declared gate executes exactly once through runtime dispatch, in registry order, and records a positive per-gate check count.
- The runtime gate list exactly matches the signed independent expected-gate manifest, and the fail-closed runner discovers and executes at least 155 tests with no skips, expected failures, or unexpected successes.
- Signed typed stage receipts, connector/projection coordinates, audit chains, registry-backed extensions, statistical/business/join projections, retrieval provenance, protected-resource errors, lifecycle inventories, and trusted cryptographic receipts pass both schema and semantic gates.

This package verdict is a reusable-design conformance result. It does not claim that an adopting runtime has executed the BDD scenarios, benchmark corpus, live authorization behavior, or service-level objectives; those remain implementation acceptance work.
