# Lessons, Gotchas, and Tuning

## Scope

This is a sanitized engineering review of the approaches that evolved in a production-scale profiling implementation. It records durable patterns without source, product, organization, vendor, dataset, table, branch, commit, or person identifiers.

The strongest lesson is that a profiler improves through **measured falsification**, not by adding more heuristics. Most important fixes came from running the system against real scale, reading rejected evidence, and discovering that a plausible algorithm could not distinguish “absent” from “not observed.”

## Evolution Summary

### Stage 1: Adaptive structural and column profiling

The initial system harvested schemas and introduced full scans for small assets, percentage sampling for medium assets, and bounded sampling for large assets. It batched wide schemas to avoid query-size limits and recorded distinct count, null rate, top values, and row/sample metadata.

**Worked**:

- Adaptive scans reduced source load.
- Column batching prevented oversized queries.
- Reusing harvested schema and profile context avoided repeated structure/count/sample calls.

**Did not work fully**:

- Early sample metadata confused source population with actual sampled rows.
- Top-value collections were treated as more representative than they were.
- A successful aggregate call could still profile zero useful values for sparse fields.

**Rule**: Store population estimate and actual rows inspected separately. Sampling configuration is not evidence that those rows were read.

### Stage 2: Semantic enrichment and evidence storage

Generated field labels and table semantics added purpose, domain, roles, identities, business context, freshness behavior, quality concerns, and related fields. Evidence moved into append-only stores.

**Worked**:

- Statistics and redacted samples substantially improved generated semantics compared with names alone.
- Batching wide assets kept prompts bounded.
- Strict requested-field membership prevented invented fields from entering storage.
- Append-only writes avoided destructive gaps during failed refreshes.

**Did not work fully**:

- Suggestive prompt language caused required structured fields to be omitted while equivalent free text was present.
- Generated output sometimes wrapped JSON in prose/fences or changed numeric types.
- Some call sites bypassed caching and repeatedly paid for identical inference.
- Individual asset domain classification produced incoherent global domains.

**Rules**:

1. Mark mandatory fields as `MUST`/`REQUIRED` and give a counterexample.
2. Add deterministic recovery from free text, but validate every recovered path against harvested structure.
3. Use strict structured output, deterministic parameters, one corrective live retry, and parse-failure telemetry.
4. Cache by evidence, source version, policy, prompt, model, and parameters—not by time alone.
5. Reconcile domains holistically across the source after per-asset extraction.

### Stage 3: Identity and grain

Identity analysis evolved from name/cardinality heuristics to structured scope/local/version identities plus exact or bounded validation.

**Worked**:

- Including scope-bearing fields prevented local IDs from being mistaken for global IDs.
- Deriving local keys as full key minus scope preserved identity semantics.
- Verified structured identities proved more reliable than weak statistical grain rows.
- Identifier-plus-version and scope-plus-identifier-plus-version strategies improved history/change-feed grain detection.
- Parsing alternative identity text into separate tuples recovered structured candidates when generated structure was missing.

**Did not work**:

- Bare local IDs collided across scopes.
- Grain-only composite generation missed stronger structured identities.
- Generic timestamps were initially tempting version markers but do not guarantee uniqueness.
- Bounded validation without duplicates could not prove global uniqueness, yet it was easy to read it as validation.

**Rules**:

- Separate entity identity from row grain.
- Treat version/revision/sequence/validity fields differently from created/modified timestamps.
- An exact duplicate proves invalidity; an incomplete sample with no duplicate proves only “not disproven.”
- Keep `validated`, `rejected`, and `unavailable` as distinct states.

### Stage 4: Relationship candidate generation

Candidate generation expanded through verified identities, key/reference names, exact and normalized names, suffix handling, value overlap, semantic types, embeddings, generated suggestions, entity references, business scenarios, and usage patterns.

**Worked**:

- Multiple independent signals improved recall.
- Exact name matches remained useful when treated as candidates rather than facts.
- Value overlap discovered aliased references.
- Semantic identity language found physically different names.
- Business scenarios revealed relationships needed for useful analysis.
- Merging duplicate candidates preserved all discovery techniques.

**Did not work**:

- Pairing every identifier-like field with every compatible field created hundreds of thousands of candidates without a reason.
- Cross-products of structured identity fields looked “semantic” but exploded cardinality.
- Normalization could strip too much and produce empty/generic stems.
- Similar names across domains produced homonym joins.
- Cardinality-ratio filters rejected valid subset/reference relationships.

**Rules**:

1. Every candidate needs a concrete signal.
2. Identity metadata is not relationship evidence by itself.
3. Names create candidates; data or authoritative constraints validate them.
4. Keep domain as risk context, not a hard boundary.
5. Preserve scenario joins as hypotheses and feed them into the same validator.

### Stage 5: Relationship validation

Validation evolved from simple dual sampling to adaptive plans: full distinct, low-cardinality complete distinct, sampled distinct, frequent-value-first, deterministic hash buckets, and one-side direct probes.

**Worked**:

- Bidirectional coverage distinguished subsets from symmetric relationships.
- Complete distinct scans were cheap and exact for small sets.
- Sampling one side and probing the other fixed high-cardinality dual-sample misses.
- Composite validation reduced accidental overlap.
- Type-aware adjustments penalized collision-prone formats and rewarded strong identifier formats.
- Semantic adjudication helped suspicious cross-domain and descriptive-field candidates.

**Did not work**:

- Independently sampling both high-cardinality sides frequently produced no intersection for real joins.
- `sample -> filter non-null -> bucket` frequently erased sparse key populations and produced false zero-distinct results.
- Top-value absence rejected valid long-tail relationships.
- Low-accuracy approximate distinct calculations returned zero for some normalized expression shapes.
- A blanket full-table bucket fix restored correctness but made large deferred queues impractically slow.
- Generated semantic adjudication sometimes rejected valid subpopulation relationships because bilateral percentages looked small.

**Rules**:

- For sparse fields: filter eligibility before deterministic hashing.
- For high-cardinality references: select one bounded side and probe the other without independently sampling both.
- Top-value overlap is positive evidence; top-value non-overlap is weak negative evidence.
- Use an approximation mode proven against representative expressions and never accept zero without an exact/alternative probe when profile evidence says non-zero.
- Prefer a hybrid validator: cheap path first, correctness-preserving fallback on a diagnostic signature such as sampled-distinct zero while population distinct is non-zero.
- An override of semantic rejection must be narrow, data-backed, logged, confidence-capped, and mutation-tested.

### Stage 6: Evidence-based foreground gating

A real run generated tens of thousands of candidates and spent many hours without finishing the foreground relationship phase. A time-budget field existed but was not enforced. Replacing it with an evidence gate reduced inline work by roughly fortyfold while preserving deferred hypotheses.

**Worked**:

- Inline validation for composite, deterministic reference, strong semantic, and observed-overlap candidates.
- Durable deferred validation for the long tail.
- Ordering by signal strength and estimated cost.
- Cross-run reuse of validated outcomes.

**Did not work initially**:

- Auto-admitting every “semantic” candidate defeated the gate because one semantic strategy was a structural cross-product, not a curated suggestion.
- The deferred queue lived only in process memory and disappeared on restart.
- The user interface presented a background single-stage job as a new foreground full run.

**Rules**:

1. Gate on direct evidence, not labels such as “semantic” or “AI-derived.”
2. Persist deferred work with idempotent keys.
3. Distinguish foreground sessions from background sub-jobs in contracts and displays.
4. Report cumulative relationship coverage separately from new relationships in one run.

### Stage 7: Trusted graph paths

Early transitive inference expanded weak direct edges into thousands of false paths. A trust gate reduced new transitive output to a small set.

**Worked**:

- Only validated semantic, deterministic reference, strong composite, or very high-confidence aligned direct edges entered the graph.
- Cycle prevention and compatible intermediate-key checks.
- Explicit path provenance and geometric/penalized confidence.

**Did not work**:

- Ungated transitive inference amplified one bad edge many times.
- Graph projections sometimes filled missing coverage with optimistic defaults.
- Path “cost” used placeholder constants and could rank unrealistic routes.

**Rules**:

- Never fill missing edge coverage with full coverage.
- Separate direct evidence from inferred navigation.
- Use real cost/selectivity estimates or label path cost unavailable.
- Apply hop penalty and weakest-edge sensitivity.

### Stage 8: Quality and anomaly scoring

Quality expanded from table-level averages to identity/key-field checks, referential integrity, format consistency, freshness, and anomaly thresholds.

**Worked**:

- Separate completeness, freshness, validity, and consistency dimensions.
- Configurable weights.
- Sanitization of non-finite numeric outputs.
- Identity-field quality tied semantic keys to data viability.

**Did not work**:

- A store shaped for field scores contained mostly table-level rows, encouraging consumers to assume field granularity.
- Silent per-reference catches removed consistency signals without affecting phase success.
- A set-membership query expanded dynamic values without a scalar cast and failed for every affected check.
- Neutral numeric defaults blurred unavailable checks with average quality.
- Freshness guessed from the first name-matched timestamp rather than reviewed temporal semantics.

**Rules**:

- Granularity is explicit in the contract.
- Failed checks produce failure evidence and affect coverage.
- Type expanded values before scalar set operations.
- Unavailable is nullable/stateful, not `0.5` by convenience.
- Freshness uses the correct event/update time and expected cadence from semantic or reviewed evidence.

### Stage 9: Manifest and agent consumption

Raw evidence was distilled into a data-model manifest and a capability manifest. Later work added latest-evidence overlays, intent mappings, quality/freshness warnings, model patterns, usage history, and graph paths.

**Worked**:

- Splitting source understanding from analysis capabilities reduced prompt load.
- Compact serialization reduced context by thousands of tokens.
- Intent-aware retrieval selected relevant assets.
- Latest semantic overlays prevented targeted refreshes from being hidden by stale narratives.
- Completeness scores told agents what evidence was missing.
- Query history and reusable transformation analysis captured how data was actually used.

**Did not work fully**:

- A typed producer and anonymous/differently-cased consumer silently dropped fields.
- Cache entries carried a version but did not always verify it at read time.
- Historical version selection mixed old manifest sections with latest profile/relationship endpoints.
- Some graph/model layers used placeholders or comments promising stronger data than the model stored.
- Manifests capped relationships globally, which could hide entire assets while reporting a healthy total.

**Rules**:

1. Share typed contracts and validate producer/consumer parity.
2. Every read is source-version scoped end to end.
3. Cache keys include source, schema, policy, evidence, and model versions; explicit invalidation remains necessary after targeted changes.
4. Measure per-asset coverage, not only global counts.
5. A manifest is a curated projection, not a copy of raw evidence tables.

### Stage 10: Source onboarding abstraction

Later design introduced a source registration facade with a short discover/profile/label/relationship/graph pipeline, source IDs, run triggers, locks, confidence degradation, and a provider seam.

**Worked**:

- Stable source identity and explicit triggers.
- Same pipeline reused for registration and reprofile.
- Concurrency lock for one source.
- Low-trust or stale sources degraded answer confidence.
- Unknown source returned a real “not found” outcome rather than a fabricated source.

**Incomplete or unsafe**:

- Stage arrays were left empty even though the contract promised per-stage status.
- Registration and status persistence happened only after profiling, so crashes could leave no durable source/run record.
- Status reads targeted only a current time partition and could miss older state.
- The short source pipeline called relationship discovery with only the new asset, limiting comparisons with the existing estate.
- Profile and semantic outputs were not always explicitly persisted in the facade path.
- Failure text risked exposing raw exception details.
- A fixed lock duration lacked renewal/fencing behavior for long runs.

**Rules for the reusable package**:

- Persist source and pending run before work.
- Persist every stage transition and count.
- Search durable state by stable key across partitions.
- Compare a new asset with an authorized existing catalog.
- Make evidence persistence explicit and verified.
- Sanitize user-visible failures.
- Use renewable leases with fencing tokens.

## Cross-Cutting Gotchas

### Stage count drift

Comments, progress totals, data models, and actual execution diverged as stages were added. A total declared as thirteen executed fourteen substeps; another run model defaulted to fewer stages than the scheduler executed.

**Fix**: Define the stage graph once in machine-readable configuration and derive UI, progress, validation, and documentation from it. Validate that each run contains exactly the applicable stage IDs.

### Presence is not completeness

Resume logic that checked whether an output table had one row could skip an incomplete stage. Existing data meant “something ran once,” not “this version completed all expected items.”

**Fix**: Resume from durable per-item receipts and reconciled expected/terminal counts.

### Write path and read path mismatch

Evidence could be written to one database/scope while readers queried another. Dynamic values arrived as several runtime representations, causing empty arrays or object strings.

**Fix**: Put source/evidence scope in every contract. Contract-test writes through a different read channel. Normalize dynamic values at connector boundaries and validate round trips.

### Additive schema was skipped when storage existed

An existence shortcut prevented new evidence fields from appearing in deployed storage and caused query failures far downstream.

**Fix**: Reapply additive schemas idempotently every startup/migration; catch permission errors after attempting, never skip because the object exists.

### Configuration precedence hid effective behavior

A local configuration edit had no effect because a higher-priority secret/provider overrode it.

**Fix**: Emit a startup provenance audit for behavior-critical settings, naming effective source without logging secrets.

### Catch-all graceful degradation can become silent data loss

Optional enrichment catches kept runs green while removing entire evidence categories.

**Fix**: Continue when appropriate, but write unavailable evidence, increment failure/coverage metrics, and surface the missing section in the manifest.

### Confidence had multiple meanings

Some confidence measured likelihood of semantic correctness, some expected join usefulness, and some profile completeness. Combining them directly produced misleading ranks.

**Fix**: Keep separate calibrated fields: correctness confidence, usefulness score, coverage, quality, freshness, and maturity.

### Cumulative vs incremental statistics

A run found few new joins because prior evidence already covered most candidates, while the user interface suggested the source had few relationships overall.

**Fix**: Report both run contribution and cumulative, version-scoped per-asset coverage.

### Tests can prove helpers but not wiring

Many isolated tests validated parsers and scorers without proving that the live stage called them, persisted output, invalidated projections, or reached agent context.

**Fix**: Add end-to-end traceability tests from source fixture to evidence to manifest to retrieval to agent plan. Mutation-test every important gate and fallback.

## Tuning Method

### Benchmark corpus

Maintain immutable cases for:

- Exact positive and negative relationships.
- Scoped identities with colliding local IDs.
- Versioned entity history.
- Sparse populated fields.
- Dense high-cardinality fields.
- Skewed distributions and long-tail overlap.
- Low-cardinality codes and integer collisions.
- Homonymous fields in different domains.
- Semantic aliases with different physical names.
- Composite keys.
- Empty/all-null/unsupported/unavailable assets.
- Nested polymorphic records.
- Citation/reference documents.
- Prompt-injection content.
- Sensitive values and deletion propagation.

### Metrics

| Layer | Metrics |
|---|---|
| Structure | Asset/field precision, recall, variant recall, version stability |
| Statistics | Relative error, rare-value recall, sample coverage, source work |
| Semantics | Field-role F1, purpose/domain agreement, hallucinated-path rate, parse rate |
| Identity | Candidate recall, validated precision, scope/version correctness |
| Relationships | Candidate recall, query-ready precision, per-asset partner coverage, validation throughput |
| Business model | Entity/event/metric agreement, scenario usefulness, evidence citation rate |
| Retrieval | Recall at $k$, nDCG, MRR, diversity, counter-evidence recall, token efficiency |
| Agent | Plan validity, query success, answer groundedness, unsupported-question refusal |
| Operations | Run success, partial rate, resume success, queue age, bytes, latency, tokens, cost |

### Acceptance rule

A tuning change passes only if:

1. Required correctness metrics do not regress beyond an approved bound.
2. The targeted metric improves on the fixed corpus.
3. Per-source-kind and difficult-case slices are reported.
4. Resource changes are reported.
5. Calibration remains acceptable.
6. The old failure is reproduced before the fix and killed after it.
7. A mutation that removes the fix causes the relevant test to fail.

## Do Not Repeat Without a Changed Premise

- Broad all-pairs field matching.
- Names-only relationship acceptance.
- Local-ID-as-global identity.
- Grain-only composite relationships.
- Independent random samples for both high-cardinality sides.
- Sample-before-filter on sparse fields.
- Top-value non-overlap as decisive rejection.
- Ungated transitive inference.
- In-memory deferred work for production.
- Output-table presence as resume completeness.
- Time-only cache invalidation.
- Generated scenario relationships as validated joins.
- Numeric neutral defaults for unavailable quality dimensions.
- Silent catch-and-skip for evidence-producing checks.
- Placeholder path costs or assumed coverage in agent-facing projections.
- Per-asset semantic classification without a holistic reconciliation pass.
