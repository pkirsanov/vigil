# Operations, Observability, and Service Objectives

## Operational Model

Profiling is a durable workflow with foreground and background work. A short foreground path establishes a minimally useful, policy-safe profile. Exhaustive or weak-evidence relationship validation, deep semantic enrichment, and historical usage analysis continue in restart-safe background queues.

## Run Modes

| Mode | Behavior |
|---|---|
| Full | Re-evaluate all applicable stages under the current method and policy versions |
| Incremental | Reuse compatible evidence and process structural/content/freshness changes |
| Resume | Continue pending work from durable checkpoints of a prior interrupted run |
| Targeted | Recompute one asset/evidence family and all dependent projections |

## Trigger Types

- Initial registration.
- Manual reprofile.
- Schedule/cadence.
- Structural drift.
- Freshness gate.
- Trust/quality gate.
- Usage drift or new relationship pattern.
- Method/policy/model version migration.

## Required Telemetry

### Run metrics

- Runs started and terminal by mode, trigger, source kind, and outcome.
- End-to-end duration.
- Completed-partial and failed rates.
- Resume success rate.
- Lease contention and stale-fencing writes blocked.
- Bytes, rows, objects, documents, events, and media duration inspected.
- Budget consumption and exhaustion.

### Stage metrics

- Items expected, attempted, completed, failed, skipped, unavailable, and not run.
- Stage duration and queue wait.
- Checkpoint age.
- Source calls, retries, throttles, timeouts, and circuit state.
- Evidence records by kind/maturity/outcome.

### Semantic metrics

- Requests, cache hits/misses, token use, latency, timeout, parse failure, corrective retry, and hallucinated-path rejection.
- Confidence distribution and calibration by evidence kind.
- Prompt truncation and omitted-evidence counts.

### Relationship metrics

- Candidates by discovery source and priority.
- Inline vs deferred counts.
- Pre-filter eliminations.
- Validation plan distribution.
- Pass, reject, unavailable, zero-match, low-coverage, timeout, and resource-failure counts.
- Sparse/high-cardinality fallback counts.
- Cumulative direct relationships and inferred paths.
- Per-asset partner coverage.
- Deferred queue depth, age, and throughput.

### Projection and retrieval metrics

- Manifest build duration and size/tokens.
- Coverage score and missing sections.
- Index build duration and lag.
- Retrieval latency, candidate counts, hard-filter counts, result count, token use, truncation, and evidence citation rate.
- Capability usage, plan validation, execution success, and unsupported-question refusal.

## Trace Model

One trace links:

```text
source registration
  -> run creation and lease
  -> connector calls
  -> stage work item
  -> sample receipt
  -> evidence writes
  -> projection/index publication
  -> agent retrieval
  -> typed read plan
  -> execution and result validation
  -> feedback evidence
```

Every evidence record stores the originating run and can be correlated to stage spans.

## Logging

Use structured fields, not interpolated prose alone:

- `run_id`, `source_id`, `source_version`, `policy_hash`.
- `stage_id`, `work_item_id`, `attempt`, `fencing_token`.
- `asset_id`, redacted `field_path_hash` when needed.
- `method`, `method_version`, `validation_plan`.
- `items_expected`, `attempted`, `completed`, `failed`, `unavailable`.
- `rows_inspected`, `bytes_read`, `model_tokens`.
- `outcome`, `reason_code`, sanitized detail.

Never log raw credentials, source values, full documents, unrestricted prompts, or full query results.

## Starting Service Objectives

These are calibration targets, not universal defaults.

| Objective | Starting target |
|---|---|
| Source registration acknowledgement | 99% under 2 seconds |
| Time to first structural profile | 95% under 5 minutes for reference workload |
| Time to minimally useful manifest | 95% under 15 minutes for reference workload |
| Manifest retrieval | 99% under 500 ms cached; 95% under 5 seconds rebuilt |
| Hybrid retrieval | 95% under 2 seconds at 50-result limit |
| Run state durability | 100% of accepted runs have durable pending record |
| Restart recovery | 99% resume without duplicated logical evidence |
| Deletion propagation | 99% within 24 hours; zero current projection leaks |
| Evidence citation | 100% of retrieved claims include evidence references |
| Query-ready relationship precision | At least 0.98 on fixed benchmark corpus |
| Required-stage zero-work false pass | 0 occurrences |

## Alerts

Alert on:

- Accepted run with no progress after lease interval.
- Stage expected count greater than zero but attempted count zero at terminal state.
- Deferred queue oldest age above objective.
- Connector auth failures or policy-denied spikes.
- Semantic parse/hallucination rejection rate drift.
- Relationship zero-distinct diagnostic spike.
- Validation unavailable rate drift.
- Manifest coverage regression.
- Index build lag behind the newest sealed but unpublished projection.
- Retrieval without evidence references.
- Deletion/revocation propagation failure.
- Calibration error above threshold.

## Recovery

### Process termination

Expired leases make work reclaimable. New workers use higher fencing tokens. Idempotency keys prevent duplicate logical evidence.

### Connector outage

Mark affected work unavailable, apply bounded retry and circuit breaker, preserve completed work, and complete the run partial or failed according to required-stage policy.

### Semantic provider outage

Continue deterministic stages, write semantic-stage unavailable evidence, publish only capabilities that do not require missing semantics, and report reduced manifest coverage.

### Projection failure

Keep the previous current manifest, do not advance the current pointer, and mark the new run partial/failed. Evidence remains available for retry.

### Corrupt cached output

Do not retry a malformed cached semantic response as if it were a transient live response. Quarantine/invalidate the cache entry, record parser/version incompatibility, and rerun explicitly.

## Capacity Planning

Track cost per:

- Asset and field profiled.
- Million source units inspected.
- Semantic field classified.
- Relationship candidate validated.
- Manifest generated.
- Retrieval request.

Separate worker pools for source reads, semantic inference, and relationship validation. Protect foreground work with reserved capacity. Use backpressure when downstream evidence or index stores lag.

## Operational Completion Gate

A run cannot be called complete unless:

- Required stage counts reconcile.
- No stage remains pending/running.
- Required projections validate.
- Current source-version pointer advances atomically.
- Index versions match the manifest.
- Consumption probes execute non-zero work.
- Telemetry shows no unhandled fault or silent-degradation counter.
