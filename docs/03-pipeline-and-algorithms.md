# Pipeline and Algorithms

## Overview

The common pipeline has nineteen logical stages. `pipeline/stages.json` is the source of truth for stage IDs, dependencies, requiredness, capabilities, and receipts; the Required column below restates its `required` flag, and the package validator fails when the two disagree.

| Stage | Inputs | Outputs | Required? |
|---|---|---|---|
| 1. Register and negotiate | Registration request, connector attestation | Effective connector capabilities | Yes |
| 2. Authorize pre-read | Caller claims, source registration, policy | Authorization scope and policy hash | Yes |
| 3. Open source boundary | Authorized source, connector | Snapshot/transaction handle or opening watermark, offset, ETag, or before-marker | Yes |
| 4. Discover structure | Metadata read only through the opened boundary | Assets, fields/paths, native constraints, final structural source version | Yes |
| 5. Classify and redact | Bounded structure/value-shape reads through the opened boundary | Handling and redaction plan | Yes |
| 6. Profile statistics | Redaction plan, source boundary | Field/content statistics and receipts | Conditional |
| 7. Extract semantics | Redaction plan, source boundary | Semantic hypotheses and embeddings | Conditional |
| 8. Validate identity and grain | Statistics, semantics | Identity and grain outcomes | Conditional |
| 9. Generate relationship hypotheses | Semantics and current evidence | Deduplicated candidates and ranks | Conditional |
| 10. Validate relationships | Candidates, source boundary, source validators | Relationship outcomes | Conditional |
| 11. Quality and freshness | Statistics, source boundary | Quality, anomalies, and freshness | Conditional |
| 12. Lineage and usage | Authorization, source boundary | Lineage and usage patterns | Conditional |
| 13. Detect model patterns | Identities, relationships, quality | Storage, hierarchy, graph, and dimensional patterns | Conditional |
| 14. Derive business model | Semantics and model patterns | Entities, events, measures, metrics, processes, scenarios | Conditional |
| 15. Verify source boundary | Opening boundary plus every evidence-producing stage | Closed/verified consistency status for the final source version | Yes |
| 16. Build indexes | Current compatible evidence under a verified boundary | Projection-scoped lexical, semantic, graph, temporal, and faceted indexes | Yes |
| 17. Build manifests | Every applicable stage terminal, projection-scoped indexes | Sealed immutable profile and capability manifests | Yes |
| 18. Consumption probes | Manifests and indexes | Nonzero retrieval and agent-readiness receipts | Yes |
| 19. Publish | Validated projections and probes | Atomic current pointer and publication event | Yes |

A `Conditional` stage runs when its capabilities and dependencies are available; when they are not, it terminates as unavailable and reduces published coverage rather than blocking the run. Current publication still requires every `Yes` stage to complete with nonzero work under a consistent source boundary.

Every terminal stage emits one signed receipt whose `stageId` structurally fixes its receipt type. Pre-discovery receipts carry a stable `sourceVersionCandidate`, `sourceVersionStatus: candidate`, and a null final `sourceVersion`; discovery derives the final structural version from bounded structure, and every later receipt carries `sourceVersionStatus: final`. Receipts also carry run/source/connector/scope/policy/taxonomy/pipeline/method/epoch/fencing coordinates, dependency-receipt IDs, exact work accounting, and one or more resolvable output bindings. Output byte hashes and item counts are verified, and the signed bundle cannot omit, reorder, or substitute a stage silently.

## 1. Registration and Capability Negotiation

1. Validate the source descriptor against its contract.
2. Resolve credentials through the credential reference in a trusted connector process.
3. Resolve caller entitlement and allowed source scope.
4. Call connector `Describe()`, pin connector implementation version, hash the canonical sorted capability set, and compare required operations with declared capabilities.
5. Build a stage applicability map.
6. Persist a pending run and immutable policy hash before source access.
7. Acquire the source lease and fencing token.

Unsupported and unauthorized are different states. Unsupported may yield a partial profile. Unauthorized blocks the run and produces no source observations.

## 2. Privacy Classification and Redaction

Pre-read authorization and native classification precede discovery. Full field/content classification follows structural discovery and precedes semantic model calls and index construction.

Signals include:

- Native source classifications.
- Field names and paths.
- Value formats.
- Entropy and length.
- Secret detectors.
- Direct-identifier detectors.
- Content policy rules.

Actions include:

- Exclude from profiling.
- Profile aggregate statistics only.
- Hash values with a source-scoped salt.
- Mask samples while preserving shape.
- Suppress small groups.
- Prevent model or embedding use.
- Restrict evidence and index visibility.

Classification itself is evidence. A heuristic policy tag remains candidate evidence unless native metadata or review confirms it.

## 3. Structural Discovery

### Stable naming

Preserve native names exactly for source access. Create separate normalized names for search and matching. Never replace native identity with a normalized display string.

### Structural capture by source kind

| Source | Capture |
|---|---|
| Table/file | Columns, order, types, nullability, constraints, partitions, views |
| Nested records | Object paths, arrays, variants, requiredness, nesting depth |
| Documents | Metadata fields, hierarchy, sections, references, media types |
| API | Operations, parameters, response paths, schemas, errors, pagination |
| Stream | Event types, envelopes, partitions, schema variants, timestamps |
| Graph | Labels, node/edge types, property types, direction, constraints |
| Media | Container metadata, tracks, duration, dimensions, transcript/optical-text availability |

### Source version

Open the source boundary before any metadata or value-shape read. For snapshot and transaction modes, every subsequent read uses the opened handle. For watermark, offset, ETag, and before/after modes, persist the opening marker and close or compare it at stage 15. Canonicalize the bounded stable structure and hash it at discovery to derive the final `sourceVersion`. The reference form is `sha256:` followed by SHA-256 over the RFC 8785 canonical object containing connector ID, connector version, connector capability hash, and the ordered structural asset/field/constraint inventory. Sort assets and fields deterministically; normalize only representation, not names. Exclude row counts, timestamps, transient error text, generated descriptions, and later semantic or statistical projections. Separate immutable opening, structure-snapshot, and verification artifacts make the boundary and source version replayable without rewriting an earlier terminal receipt.

For document collections, maintain both a collection-structure version and per-document content hashes. For streams, maintain envelope/event-schema versions independently from event volume.

`sourceVersion` identifies structural content only. A `projectionId` is assigned once every applicable profiling stage has terminated; indexes are stamped with it, and the manifests embed those indexes. `manifestVersion` identifies that immutable assembled projection, while `contentHash` cryptographically seals the RFC 8785 canonical manifest body, including authorization scope, policy hash, evidence cutoff, taxonomy, pipeline, method/model/prompt versions, and embedded index versions. The body seal is computed only after the indexes exist, so no published artifact is rewritten. Structural change creates both a new source version and a new manifest version; new evidence, validation, policy, or semantic methods create only a new manifest version. APIs never use one coordinate as a substitute for the other.

Connector behavior is also immutable input: connector ID, implementation version, and canonical capability hash appear on runs, evidence, parser/model receipts, indexes, manifests, retrieval/read results, and stage receipts. A connector implementation or capability change therefore requires a new compatible projection even if source structure is unchanged.

## 4. Sampling

### Principles

- Full scan small populations.
- Prefer deterministic hash samples over random samples for reproducibility.
- Stratify by partition and time when distributions vary.
- Preserve rare values and schema variants deliberately.
- Record actual work; requested sample size is not evidence.
- A failed or empty sample is not evidence that the source is empty.

### Sample receipt

Every sample-derived observation records:

```text
population estimate
actual units inspected
method and parameters
seed or hash-bucket predicate
partitions/time windows represented
exact vs approximate
estimated error bound
failed or excluded strata
```

### Tabular sampling

Suggested planner:

1. Population at or below exact ceiling: full scan.
2. Partitioned/time-varying: deterministic sample per partition and time bucket.
3. Sparse fields: filter eligibility before deterministic hash bucket, not random sample before filter.
4. High-cardinality identity validation: sample one side and probe the other side or use hash buckets on normalized keys.
5. Low-cardinality sets: complete distinct scan.

### Document sampling

Stratify by content type, size, language, age, owner scope, and source partition. Preserve short and long documents and rare formats. Chunk after document selection so a few long documents do not dominate the sample.

### Stream sampling

Use bounded windows across recent and historical periods, partitions, and event types. Track late arrival, out-of-order rate, duplicate keys, and schema variants. Reservoir samples alone are insufficient for state-transition analysis.

## 5. Statistical Profiling

### Common statistics

- Population and sample counts.
- Missing/null/empty ratio.
- Approximate and exact distinct count.
- Frequency distribution and top values after redaction.
- Min/max, mean, variance, standard deviation.
- Quantiles and interquartile range.
- Entropy and concentration.
- Length and token distributions.
- Type and format variants.
- Temporal minimum, maximum, cadence, gaps, seasonality, and late arrival.
- Array length and nesting distributions.
- Outlier counts and robust scores.

Every served field profile accounts for the fixed families `missingness`, `cardinality`, `distribution`, `format`, `temporal`, `outlier`, and `nesting`. Each family reports `passed`, `failed`, `unavailable`, or `not-applicable` with a reason where needed. The profile also pins method/version, exactness, sample evidence, sample coverage, and minimum group size. An empty statistics object is invalid, and sampled distinct counts are explicitly labelled approximate.

### Numeric profile

Prefer mergeable sketches for distributed profiling. Record algorithm, parameters, and expected relative error. Treat non-finite values as their own category. Do not coerce overflow or parse failure to zero.

### Categorical profile

Track distinct count, top-$k$, entropy, dominance, tail mass, and new-value rate. A low-cardinality integer may be a code, state, or flag—not a measure.

### Text profile

Track length, language, character classes, token count, structured patterns, secret/identifier risk, and duplicate/similarity rate. Do not publish raw text samples by default.

### Nested profile

Track path presence, type variants, array item schema, object-key distribution, depth, and co-occurrence. A path absent in a sample is not declared absent from the population unless an exact scan or authoritative schema proves it.

### Quality dimensions

Let each dimension be nullable when not applicable or unavailable. A composite quality score must renormalize only across evaluated dimensions and carry the evaluated set.

Example starting model:

$$
Q = \frac{\sum_i w_i q_i I_i}{\sum_i w_i I_i}
$$

where $I_i=1$ only when dimension $i$ was evaluated. When $\sum_i w_i I_i = 0$, $Q$ is unavailable rather than numeric. Never substitute a neutral value for an unavailable dimension.

## 6. Semantic Enrichment

### Evidence pack

Build one bounded pack per asset:

- Native name, kind, and structural type.
- Field paths and physical types.
- Statistics and redacted value-shape examples.
- Neighbor fields.
- Native constraints and lineage.
- Previously validated identities and relationships.
- Existing glossary and reviewed annotations.

Send full names/types as context but only a bounded batch for classification. Require strict output and exact field-path membership.

### Output

- Field roles and business meanings.
- Asset purpose and domain candidates.
- Identity, grain, and storage-pattern hypotheses.
- Freshness behavior and quality concerns.
- Related fields and aliases.
- Lineage hints.
- Business entity, event, process, measure, metric, and scenario hypotheses.

### Reliability controls

- Deterministic temperature.
- Explicit maximum input characters and output tokens.
- Stable cache key from evidence, model, prompt, and policy versions.
- Markdown-fence removal only as transport cleanup.
- Strict schema validation.
- One corrective retry for a live malformed response.
- No live retry for a malformed cached response; invalidate or flag parser drift.
- Reject invented asset and field names.
- Store prompt hash and model reference, not sensitive prompt payload, by default.

Every semantic invocation and cache decision conforms to `contracts/model-execution.schema.json`. Provider, model deployment digest, connector coordinate, prompt, contracts, parameters, redacted input, source version, authorization scope, policy, cache namespace, usage, outcome, and output digest are pinned independently. Admission precedes execution and deployment region must be allowed for the source residency class. A time-to-live never substitutes for these bindings, and a cache hit must cite the original execution.

## Typed Read Plans

The current result contract represents one operation-attributed bounded table, so a read plan contains exactly one operation. This supports every typed operation kind independently without flattening heterogeneous results. A future multi-operation plan must first add stable operation IDs and discriminated per-operation results with outcome, cursor/window state, truncation, and failed/not-run accounting.

### Deterministic fallback

Fallback parsers may extract exact field names from generated narrative and build lower-confidence structured hypotheses. They must:

1. Match names against harvested structure.
2. Preserve alternative branches rather than combining incompatible alternatives.
3. Record their method separately from model inference.
4. Never mark output validated.

## 7. Identity and Grain

### Identity model

```text
scope paths + local key paths = entity identity
entity identity + version paths = versioned row identity
row identity or event identity = grain
content hash = content identity
```

### Candidate order

1. Authoritative constraints or explicit IDs.
2. Reviewed structured identities.
3. Generated structured identities.
4. Deterministic scope/local/version patterns.
5. Statistical uniqueness candidates.

### Validation

For a candidate key $K$:

- Verify every path exists in the pinned source version.
- Count total eligible units $N$.
- Count missing-key units $M$.
- Count distinct complete keys $D$.
- Count duplicate key groups and maximum group size.

Exact validation passes when $N>0$, $M=0$, and $D=N$. A policy may allow lower completeness for conceptual entity identity, but row identity must remain strict.

If exact validation exceeds a budget, run a bounded deterministic validation. If it finds a duplicate, reject. If it finds none but covers less than the population, return unavailable or sampled-support—not validated uniqueness.

### Versioned data

When an entity identifier repeats and a revision, sequence, validity, or effective-time marker exists, the system must expose both:

- Entity identity without the version marker.
- Row grain with the version marker.

This prevents entity-level joins from becoming revision-level joins accidentally.

## 8. Relationship Discovery

### Candidate sources

| Signal | Typical priority | Notes |
|---|---|---|
| Authoritative constraint | Highest | Still check source-version validity |
| Verified composite identity alignment | High | Preserve scope and component order |
| Primary/foreign reference pattern | High | Require type/format compatibility |
| Explicit document/API reference | High | Resolve target and access scope |
| Scenario or model suggestion | Medium | Analytical need, not proof |
| Exact or normalized name | Medium | High homonym risk |
| Shared redacted values | Medium/high | Strong positive, weak negative |
| Semantic role or embedding similarity | Medium | Must not bypass source validation |
| Co-usage or lineage | Medium | Usage evidence, not row overlap |
| Generic compatible types | Reject | No concrete relationship signal |

Merge duplicate candidates and retain all discovery techniques.

### Candidate score

A starting rank within a priority tier:

$$
H = 0.35h + 0.25e + 0.20s + 0.15n + 0.05u
$$

where $h$ is deterministic signal strength, $e$ semantic similarity, $s$ semantic-token overlap, $n$ name-token overlap, and $u$ validated-neighbor or usage support. This orders validation; it is not relationship confidence.

### Inline gate

Validate inline only when at least one strong channel exists: authoritative constraint, composite alignment, deterministic reference pattern, exact name with viability, high semantic similarity, or observed value overlap. Persist everything else to the durable queue.

### Validation planner

| Situation | Plan |
|---|---|
| Small or low-cardinality sets | Complete distinct comparison |
| Composite key with bounded side | Complete smaller side, probe larger side |
| High-cardinality identity | One-side deterministic sample, full-side probe |
| Sparse key | Eligibility filter then deterministic hash bucket |
| Skewed distribution | Frequent values plus deterministic tail bucket |
| Documents | Resolve explicit references, entity co-reference, citation target |
| APIs | Contract reference plus sampled response confirmation |
| Streams | Correlation-key overlap plus temporal-window alignment |
| Graphs | Native edge existence and endpoint type validation |
| Multimodal | Shared identifier, timestamp, provenance, or reviewed semantic link |

### Normalization

Normalize each component according to a compatible family. Examples: case-folded text, canonical numeric, canonical identifier, normalized path, normalized URI, normalized timestamp. Composite keys require every component present; concatenate only after component-level normalization.

### Coverage

For distinct key sets $L$ and $R$:

$$
C_L = \frac{|L \cap R|}{|L|}, \qquad C_R = \frac{|L \cap R|}{|R|}
$$

Record both. If either denominator is zero, that side's coverage is unavailable rather than zero. One-sided high coverage may be a valid subset/reference relationship. Do not collapse them into one symmetric percentage.

### Confidence

Relationship confidence combines coverage, matches, source, validation exactness, type/format, semantic alignment, and counter-evidence. It measures expected correctness/usefulness under the source version. It does not replace validation status.

Absolute match floors apply only to approximate sparse evidence. An exact or authoritative relationship over a small population can be query-ready when coverage and semantics are strong even if it has fewer than the configured approximate-evidence match floor.

### Rejection and unavailability

- Zero matches after an exact or authoritative check: rejected for this source version.
- Zero matches from a bounded check: insufficient support unless a confidence bound proves overlap is below policy; otherwise execute an exact or one-side-probe fallback.
- Query timeout, permission failure, unsupported operation, or zero-work sample: unavailable.
- Coverage below policy: validated observation but not query-ready.

### Transitive paths

Only validated/curated direct edges can seed a path. Require compatible intermediate keys and no cycles. Apply both weakest-edge sensitivity and hop penalty:

$$
P = \min(e_i) \times (1-p)^{h-1}
$$

where $p$ is hop penalty and $h$ is hop count. An inferred path carries zero direct matching rows and is never represented as a direct relationship.

## 9. Enhanced Model Detection

### Storage patterns

Detect current state, event log, transaction, periodic snapshot, accumulating snapshot, entity history, hybrid current/history, audit, soft delete, bi-temporal, and materialized projection patterns. Use identity/grain, temporal distributions, repeated entities, and lineage—not names alone.

### Field roles

Classify identity, scope, version, reference, temporal, measure, categorical, ordinal, boolean, descriptive, label, path, status, nested, media, and policy roles. Preserve multiple roles when appropriate.

### Table/asset roles

Classify fact, dimension, bridge, hierarchy, edge, reference, aggregate, configuration, audit, document collection, and media collection. Store heuristic and semantic verdicts separately; disagreements become review evidence.

### Functional dependencies

For determinant $X$ and dependent $Y$, estimate violation rate:

$$
V = \frac{|\{x : |Y_x| > 1\}|}{|X|}
$$

This is a determinant-group violation rate and is unavailable when $|X|=0$. Also record a row-weighted violation rate so a tiny and a dominant determinant group are not treated equally. Only low-violation dependencies become grouping guidance. A dependency does not imply a relationship to another asset.

### Enum catalogs

Use complete distinct scans for bounded cardinality. Store observed values separately from generated descriptions and order. Redact or hash values when policy requires it. A catalog with sampled values is incomplete and must say so.

### Lineage and reusable transformations

Parse native transformations, routines, projections, and query histories to extract references, joins, filters, computed fields, output schemas, metrics, and assumptions. Parsing should use a source language parser when possible; regular expressions are fallback evidence, not authoritative syntax analysis.

## 10. Business Model Extraction

See the canonical model in `04-evidence-and-business-model.md`. Synthesis happens after identities, relationships, quality, and lineage because those facts constrain business interpretation.

## 11. Manifest and Index Construction

1. Select evidence for the pinned source and policy versions.
2. Resolve supersession by stable logical key.
3. Preserve unresolved conflicts.
4. Apply maturity thresholds per manifest section.
5. Calibrate confidence.
6. Build asset, field, identity, relationship, quality, lineage, and business projections.
7. Cap and diversify; record every omission.
8. Redact values.
9. Validate contracts and evidence references.
10. Build versioned indexes.
11. Run retrieval and agent-consumption probes.
12. Publish atomically.

## 12. Incremental and Resume Semantics

### Incremental

Reuse evidence only when source version, policy hash, method version, and evidence dependencies remain compatible. Fresh statistics may expire without a structural version change. Model or prompt changes invalidate only their inference layer and dependent projections.

### Resume

Resume from durable work records, not from the presence of any row in an output table. “Some rows exist” does not prove stage completeness. Stage coverage must reconcile expected and terminal item counts.

### Targeted refresh

A change to one asset or one semantic annotation invalidates dependent identities, relationships, graph paths, business concepts, manifests, and indexes through an explicit dependency graph. It must not leave stale derived projections current.
