# Agent Consumption

## Objective

The profiler is useful only when an agent can consume its products without re-reading the entire source, guessing relationships, or treating a generated narrative as truth. Consumption must therefore be progressive, version-scoped, policy-filtered, compact, and evidence-cited.

## Two Manifest Layers

### Profile manifest

Use for structural reasoning, source exploration, relationship planning, quality analysis, and explanation. It contains assets, fields, identities, grain, relationships, business model, lineage, quality, freshness, conflicts, and coverage.

### Capability manifest

Use for task planning. It maps question patterns to required assets, validated relationships, metrics, result shapes, constraints, warnings, and evidence. It is smaller and should be loaded before detailed source context.

## Progressive Disclosure

An agent should not inject the full profile into every turn.

```mermaid
flowchart LR
    A[Question] --> B[Capability lookup]
    B --> C[Relevant concepts and assets]
    C --> D[Validated paths and warnings]
    D --> E[Field-level detail]
    E --> F[Generate typed read plan]
    F --> G[Validate plan]
    G --> H[Execute]
    H --> I[Assess result and cite evidence]
```

Recommended layers:

1. **Routing layer**: capability names, question patterns, business concepts, source coverage, and warnings.
2. **Planning layer**: required assets, validated relationships, grain, metric contracts, temporal coverage, and policy constraints.
3. **Execution layer**: exact fields, physical types, enum catalogs, source-native operation constraints, and estimated cost.
4. **Evidence layer**: supporting and counter-evidence, validation receipts, freshness, and quality.

## Retrieval Contract

Every request includes:

- Authorized source ID.
- Exact source version.
- Exact manifest version, unless the caller deliberately invokes the separate current-resolution endpoint first.
- Purpose: discovery, planning, query generation, validation, or explanation.
- Natural-language query.
- Minimum maturity, ranked by `maturityRank` in `taxonomies/evidence-kinds.yaml` rather than by list position, so a directly observed fact outranks a generated hypothesis.
- Token budget.
- Whether counter-evidence is required.

Every response includes:

- The complete sealed projection coordinate: source/manifest/projection versions, connector ID/version/capability hash, scope, policy, taxonomy, pipeline, method set, evidence cutoff, and revocation epoch.
- Ranked items.
- Per-item score explanation.
- Maturity and confidence.
- Evidence references.
- Warnings and conflicts.
- Coverage and truncation receipt with separate considered, returned, and omitted counts for items, caveats, and conflicts.
- Evidence-backed caveats and disjoint supporting/counter-evidence sets for every conflict.

Re-presenting a stale coordinate to plan validation returns `valid: false` with a reason code.

## Retrieval Pipeline

### 1. Hard gates

Apply before ranking:

- Caller authorization and entitlement-scoped index namespace selection before candidate generation.
- Source and policy version.
- Asset/field policy tags.
- Required maturity.
- Validity window.
- Deletion/revocation state.

### 2. Candidate generation

- Lexical exact/prefix/fuzzy matches for native names, aliases, glossary, enum values, and error terms.
- Semantic vector matches for business questions and concept descriptions.
- Graph expansion from matched concepts to assets, fields, metrics, and validated paths.
- Temporal filtering for requested windows and freshness.
- Facets for source kind, domain, role, quality, policy, maturity, and capability.
- Usage evidence for repeated successful paths.

### 3. Ranking

Combine evidence strength, relevance, usage, freshness, quality, path quality, and cost. Return score components for auditability. Do not hide a low-quality source merely because it is semantically relevant; return the warning with it or withhold it if policy requires.

### 4. Diversity and conflict

Avoid filling the context with near-duplicate fields from one asset. Include:

- Multiple plausible interpretations for ambiguous terms.
- At least one counter-evidence item when material.
- Relevant quality/freshness constraints.
- A direct relationship in preference to an inferred path.
- A reviewed or usage-proven concept in preference to a generated synonym.

### 5. Compression

Compress in this order:

1. Remove duplicate wording while preserving evidence IDs.
2. Cap low-ranked fields per asset.
3. Prefer summaries plus expandable evidence references.
4. Drop low-maturity hypotheses before validated evidence.
5. Preserve warnings, conflicts, grain, and relationship predicates.
6. Record omitted item counts by section.

The omission vocabulary is closed to `items`, `caveats`, and `conflicts`. Each section reconciles independently, and `truncated` plus its reason must agree with whether any section omitted content.

## Agent Planning Rules

1. Resolve business terms to concepts and alternatives.
2. Select a capability only when its required evidence is current and available.
3. Use entity identity and row grain to predict duplication and aggregation level.
4. Use only query-ready direct relationships for automatic joins.
5. Use inferred paths only when the plan explicitly traverses every validated edge.
6. Check temporal coverage and freshness before applying recent time windows.
7. Check quality constraints for fields used as filters, groupings, identities, or measures.
8. Check metric grain, units, denominator, null behavior, and required relationships.
9. Produce a typed single-operation read plan using connector capabilities; never execute raw source content. Do not compose multiple or heterogeneous operations until the API exposes operation-attributed result unions.
10. Validate referenced assets/fields, operations, cost, and authorization before execution.

## Answer Confidence

Answer confidence is not the maximum confidence of retrieved evidence. It is bounded by the weakest required claim.

Suggested calculation:

$$
A = \min(C_s, C_i, C_r, C_m, C_f, C_q) \times K
$$

where:

- $C_s$: structural coverage.
- $C_i$: identity/grain support.
- $C_r$: relationship/path support.
- $C_m$: metric or semantic support.
- $C_f$: freshness.
- $C_q$: quality.
- $K$: result-validation factor.

Missing required evidence makes the capability unavailable rather than assigning a convenient low number.

## Result Analysis Loop

An agent may iterate under explicit budgets:

1. Plan from capability and profile evidence.
2. Generate typed connector operations.
3. Validate the operations.
4. Execute bounded reads.
5. Assess whether the result answers the question.
6. On empty results, distinguish valid empty data from wrong interpretation, stale data, unavailable relationship, and transport failure.
7. Refine within round, time, token, and source-read budgets.
8. Synthesize with citations and remaining unknowns.

An empty result is data, not automatically failure. A request that never executed is not an empty result.

## Unsupported Questions

Refuse or qualify when:

- Required source is unauthorized.
- Requested historical version is unavailable.
- Required relationship is only a hypothesis or rejected.
- Metric formula lacks validated grain or denominator.
- Data freshness does not cover the requested period.
- Quality or sample coverage makes the result materially unreliable.
- A source capability needed for the plan is unsupported.

The response should name the missing evidence category and the next profiling or review action—not invent a query path.

## Feedback Loop

Record privacy-filtered outcomes:

- Which capability and evidence were used.
- Whether the typed plan validated.
- Whether execution succeeded.
- Whether result shape and row counts were plausible.
- User or agent correction.
- Latency, cost, and source work.

Positive usage raises rank and can make an already validated capability usage-proven only through a resolvable, independently signed usage-proof artifact bound to an independently pinned issuer registry. Self-reported counters are insufficient. Usage does not validate a new relationship or source version. Repeated failures create time-bounded suppression and targeted revalidation, not permanent deletion.

## Example Agent Tool Set

| Tool | Purpose |
|---|---|
| `list_capabilities` | Route a question without loading full structure |
| `retrieve_intelligence` | Hybrid retrieval under version and token budget |
| `get_asset_profile` | Expand one asset and its fields |
| `get_relationships` | Get direct validated relationships and separate inferred paths |
| `find_paths` | Find bounded paths over trusted graph edges |
| `get_metric_contract` | Retrieve formula, grain, units, filters, and evidence |
| `get_quality_and_freshness` | Retrieve constraints for proposed fields/assets |
| `validate_read_plan` | Check schema, operations, joins, cost, policy, and source version |
| `execute_read_plan` | Execute only a validated typed single-operation read plan and return one operation-attributed bounded result |
| `submit_feedback` | Append confirmation, rejection, or revalidation evidence |

## Consumption Acceptance Gates

- Every planned asset and field resolves in the pinned manifest.
- Every automatic relationship is validated for the pinned source version.
- Every metric identifies its grain and dependencies.
- Every result includes source version and trace ID.
- Every result and retrieval response carries the same complete connector/projection coordinate as its validation receipt.
- Every answer cites profile and execution evidence.
- Every truncation has a coverage receipt.
- Every unsupported conclusion remains unknown rather than receiving a default.
- Prompt-injection content in source data cannot alter the plan or tools.
