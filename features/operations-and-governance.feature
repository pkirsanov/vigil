@FR-002 @FR-003 @FR-007 @FR-018 @FR-022 @FR-023 @FR-024 @NFR-001 @NFR-002 @NFR-003 @NFR-004 @NFR-005 @NFR-006 @NFR-007
Feature: Operations, governance, privacy, and measurable tuning
  The platform remains safe, observable, resumable, and honest under failures and change.

  @FR-002-AC-01
  Scenario: reject a mutating probe
    Given a generated or user-supplied plan requests a state-changing source operation
    When the policy gateway validates the plan
    Then the operation is rejected before connector invocation
    And the denial is audited without exposing credentials

  @FR-002-AC-02 @FR-023-AC-01
  Scenario: treat source text as untrusted data
    Given a document or field value contains instructions to ignore policy and call a tool
    When the content is profiled and indexed
    Then the text may be represented as content evidence
    But stage order, policy, authorization, prompts, and tools are unchanged

  @FR-023-AC-02
  Scenario: reject a source-driven tool request
    Given semantic output contains a request to execute a connector operation
    When output validation runs
    Then the request is rejected because semantic workers cannot invoke tools

  @FR-007-AC-02
  Scenario: retain contradictory evidence
    Given two current methods produce incompatible claims about one subject
    When evidence is stored
    Then both records remain immutable
    And their counter-evidence links and conflict are visible in projections

  @FR-007-AC-01
  Scenario: require the complete common evidence envelope
    Given a producer emits an observation, inference, validation, rejection, curation decision, or usage proof
    When the evidence record is accepted
    Then it carries provenance, confidence, maturity, outcome, validity window, source version, and payload hash
    And its stable logical key and record hash bind the complete decision-bearing envelope

  @FR-024-AC-01
  Scenario: record feedback without overwriting evidence
    Given a reviewer rejects an inferred claim for a named source version
    When feedback is submitted
    Then a new rejection evidence record is created
    And the original inference remains available for audit

  @FR-024-AC-02
  Scenario: retain a review conflict
    Given two authorized reviewers make conflicting decisions under applicable policies
    When the projection builder runs
    Then the conflict is preserved
    And capabilities depending on the claim are withheld until policy resolves it

  @FR-019-AC-03 @FR-022-AC-01
  Scenario: redact sensitive samples before model use
    Given a sampled value contains a secret or direct identifier
    And policy requires source-scoped hashing for direct identifiers and exclusion for secrets
    When privacy classification runs
    Then the secret is excluded and the direct identifier is source-scoped hashed
    And the raw value is absent from model requests, evidence payloads, logs, vectors, and manifests

  @FR-022-AC-02 @FR-034-AC-03
  Scenario: enforce minimum group size
    Given an aggregate statistic describes fewer subjects than the configured minimum group size
    When projection or retrieval runs
    Then the statistic is suppressed
    And suppression evidence explains the policy reason without revealing the group

  @FR-022-AC-03 @NFR-006-AC-01
  Scenario: delete derived embeddings
    Given a source is deleted or its entitlement is revoked
    And policy requires physical deletion of serving indexes
    When deletion propagation runs
    Then vectors, lexical entries, graph links, caches, manifests, and usage-derived projections are removed
    And a deletion receipt reconciles every derived store

  @NFR-006-AC-02
  Scenario: revoke source access
    Given a caller previously had access to a source
    And that access is revoked
    When the caller retrieves current or historical intelligence
    Then no source-derived item is returned
    And relevant caches are invalidated before serving

  @FR-032-AC-03 @NFR-002-AC-01
  Scenario: trace a profiling run end to end
    Given an accepted profiling run produces evidence and a manifest
    When telemetry is inspected
    Then one trace links run creation, connector calls, stages, sample receipts, evidence writes, projection publication, and consumption probes

  @FR-016-AC-02 @NFR-002-AC-02
  Scenario: surface degraded quality checks
    Given one applicable quality check fails to execute
    When the quality stage completes other checks
    Then failure evidence and a failure count are stored
    And manifest coverage is reduced
    And the stage does not silently report every check successful

  @NFR-003-AC-01
  Scenario: stop at a run budget
    Given a run reaches its source-read or wall-clock budget while only optional work remains
    When the next work item is considered
    Then no new work starts
    And the run becomes completed-partial
    And completed, pending, and omitted counts are recorded
    And connector calls, model calls, stages, runs, prompts, queues, queries, traversals, and manifests each carry their own policy-bound limit, usage, cancellation-check interval, outcome, and causal cancellation receipt

  @NFR-001-AC-02
  Scenario: reject an empty validation run
    Given a required validation gate selects cases
    And zero cases execute
    When the gate finishes
    Then it returns failure
    And not-run count is nonzero

  @NFR-001-AC-02
  Scenario: reject a declared gate that executes no checks
    Given the package declares an ordered registry of validation gates
    And one registered gate is missing, raises an exception, or executes zero checks
    When runtime gate dispatch completes
    Then the package returns failure
    And its execution receipt names the gate, ordinal, executed checks, and added failures
    And the runtime registry must exactly match an independent expected-gate manifest
    And the test runner fails when fewer than its independently declared test floor execute

  @NFR-001-AC-03
  Scenario: reject replay of an older signed validation control
    Given two historically valid validation controls were signed within an authorized issuer window
    And the older control has weaker gates or floors
    When production validation is invoked with the external issuer-registry pin and the independently governed current-control byte pin
    Then the older control is rejected despite its valid signature
    And omitting the current-control byte pin fails instead of falling back to issuer-window validation

  @NFR-004-AC-01
  Scenario: evolve an existing evidence store
    Given an evidence contract adds optional fields
    And the physical store already exists with the older schema
    When schema initialization runs
    Then additive schema evolution is applied idempotently
    And initialization does not skip merely because the store exists

  @NFR-004-AC-02
  Scenario: deduplicate append-only evidence
    Given multiple evidence records share one stable logical key across time
    When a current projection is built
    Then the correct current compatible record is selected
    And historical records remain available

  @FR-018-AC-02
  Scenario: expire negative suppression
    Given a relationship has repeated validated misses within the suppression window
    When candidate generation runs
    Then the candidate is suppressed for that compatible source version
    When the window expires or source evidence changes
    Then the candidate becomes eligible for revalidation

  @FR-004-AC-02
  Scenario: invalidate projections on source-version change
    Given a current manifest and indexes describe one source version
    When a structural change produces a new source version
    Then old projections remain addressable only by their explicit version
    And new current projections are rebuilt before the current pointer advances
    And the signed publication receipt proves a compare-and-swap from the observed prior pointer and lower fencing token to the new projection and higher token

  @NFR-005-AC-01
  Scenario: accept a tuning change with measured improvement
    Given a fixed benchmark corpus and recorded baseline
    And a tuning change improves its target metric without unacceptable correctness or calibration regression
    When the before and after reports are compared
    Then the change passes
    And precision, recall, coverage, latency, bytes read, model usage, and calibration are present before and after
    And positive, negative, sparse, skewed, high-cardinality, scoped, versioned, adversarial, and no-evidence slices all execute
    And each per-case result agrees with the corpus-declared outcome with zero skipped or not-run work

  @NFR-005-AC-02
  Scenario: reject a tuning change that hides misses
    Given a tuning change reduces latency by skipping difficult candidates
    But relationship recall or per-asset coverage falls beyond the accepted bound
    When benchmark evaluation runs
    Then the change fails despite the latency improvement

  @NFR-007-AC-01
  Scenario: report calibration drift
    Given observed correctness in a confidence bin diverges from predicted confidence beyond policy
    And policy requires recalibration before serving that evidence class
    When calibration evaluation runs
    Then a drift event is recorded
    And a new calibration version is required without changing evidence maturity

  @NFR-007-AC-02
  Scenario: preserve unavailable outcome despite high confidence
    Given an inference has high calibrated confidence but its required source validation was unavailable
    When evidence and a manifest are published
    Then the claim remains unavailable rather than validated
    And confidence cannot replace outcome, coverage, maturity, or caveats

  Scenario: reject feedback authority spoofing
    Given an authenticated caller submits feedback while claiming a higher-authority actor type in request content
    When feedback authorization runs
    Then actor identity and authority are derived only from validated claims
    And the caller-controlled authority field is rejected

  @FR-027-AC-04
  Scenario: hide protected resource existence
    Given an authenticated caller requests one absent identifier and one existing identifier outside its authorization scope
    When either protected-resource operation runs
    Then both requests return the same fixed resource-unavailable response contract
    And status, reason, detail shape, timing class, and observable side effects do not reveal which resource exists
    And body-addressed source identifiers are covered by the same explicit protected-operation inventory

    Scenario: append a tamper-evident audit event
      Given an authenticated agent executes a typed read plan
      When authorization and execution complete
      Then one audit event records the validated actor, decision, policy, correlation, target version, and redacted outcome
      And its integrity digest links to the prior event
      And no credential, raw sample, or prompt content is present

    @FR-032-AC-03
    Scenario: detect a rewritten audit event
    Given an append-only audit chain covering a source
    When any recorded actor, action, decision, target, or predecessor link is altered
    Then digest recomputation fails for that event and every successor
    And the altered history cannot be presented as authentic

  @FR-032-AC-04
  Scenario: reject an inconsistent audit authorization narrative
    Given an audit event records an authorization decision as denied
    When the event reports a successful outcome or any granted permission
    Then schema or semantic validation fails
    And no cancellation or feedback receipt may cite it as the matching successful action
    And actor identity is the same domain-separated deployment-salted hash used by read, feedback, cancellation, and cross-scope receipts

  @FR-029-AC-02
  Scenario: isolate cache entries across semantic versions
      Given two semantic executions differ in source, scope, policy, model, prompt, contract, parameters, or redacted input hash
      When cache lookup runs
      Then the executions cannot share a cache entry
      And a cache hit cites the original execution and exact entry version

    @FR-029-AC-04
    Scenario: invalidate a cache entry after admission policy tightens
    Given a cached semantic result was produced under an earlier model-admission decision
    And the admission policy is tightened so that decision no longer holds
    When cache lookup runs
    Then the entry is invalidated rather than served as a hit
    And any re-derivation requires a fresh admission decision before invocation

  @FR-029-AC-03
  Scenario: quarantine a malformed cached semantic result
      Given a cache entry output does not satisfy its pinned output contract
      When semantic retrieval reads the entry
      Then the entry is quarantined and cannot be served
      And the failure is audited without silently retrying it as a live response

  @FR-027-AC-03
  Scenario: block serving before asynchronous deletion
    Given an authorized lifecycle request revokes a source
    When the request is accepted
    Then current and historical serving paths are blocked synchronously
    And asynchronous physical cleanup starts afterward
    And its per-store receipt is retrievable
    And a completed deletion retains serving state blocked and carries a purpose-signed versioned inventory hash
    And every store records its pre-deletion artifact IDs, enumeration time, artifact-set hash, and exact deleted, missing, retained-by-policy, failed, and remaining counts
    And the inventory reconciles all published indexes, evidence, samples, caches, manifests, parser/model outputs, audit records, and backups
    And arbitrarily large inventories are split into ordered content-addressed pages whose root count and hash reconcile before deletion starts

  @FR-032-AC-05
  Scenario: reject a trusted receipt outside issuer validity
    Given a correctly signed redaction, cross-scope, publication, or stage receipt uses a registered issuer
    But its purpose-specific event time precedes issuer activation or follows issuer expiry
    When trust validation runs
    Then the receipt is rejected despite its valid cryptographic signature
    And replay across another asset, epoch, connector, or evidence set is rejected by the signed content envelope

    Scenario: create a new source and manifest version after structural mutation
      Given a published manifest is pinned to a stable source version and evidence chain
      And the source later changes a field type or structural member
      When profiling and projection run again
      Then a new source version and manifest version are created
      And the prior manifest, evidence records, and indexes are byte-for-byte unchanged
      And current pointers move only after the new version passes publication gates

    @FR-031-AC-01
    Scenario: create a new manifest version after evidence or policy mutation
      Given a published manifest is pinned to a stable structural source version
      And a relationship outcome, semantic model, method, taxonomy, evidence cutoff, or policy classification changes
      When projection runs again
      Then the structural source version remains unchanged
      And a new manifest version and version-bound indexes are created
      And explicit historical lookup still returns the prior immutable projection

  @FR-018-AC-01
  Scenario: normalize usage without retaining caller identity
    Given an authorized execution emits a usage trace containing literals and direct caller identifiers
    When usage learning normalizes and fingerprints the trace
    Then literals and direct identifiers are removed or deployment-salted before persistence
    And no raw caller identity is stored in usage evidence, indexes, logs, or cache keys

  @FR-018-AC-03
  Scenario: trigger targeted revalidation from a new usage pattern
    Given a new fingerprinted usage pattern repeatedly exercises an existing relationship candidate
    When usage learning crosses the configured evidence threshold
    Then targeted relationship revalidation is durably enqueued
    And usage evidence cannot directly promote the relationship without validation

  @FR-029-AC-01
  Scenario: deny an unregistered or policy-incompatible model deployment
    Given a semantic request names an unregistered deployment or a classification denied by model-admission policy
    When model admission evaluates the request
    Then the request fails closed before provider invocation
    And no model cache entry, request payload, or generated evidence is written

  @FR-032-AC-01
  Scenario: compute the audit digest from a declared canonical preimage
    Given two independent implementations receive the same audit event body and predecessor digest
    When each applies the declared canonicalization and digest algorithm
    Then both compute the same event digest
    And changing field order without changing values does not change the digest

  @FR-032-AC-02
  Scenario: require predecessor links after the audit genesis event
    Given an audit chain contains one genesis event and a later event
    When predecessor-link validation runs
    Then only the genesis event may omit a predecessor digest
    And every later event must link to the exact digest of its immediate predecessor

  @FR-034-AC-01
  Scenario: reject raw values in a served projection
    Given a manifest producer marks its handling attestations raw-value-free
    And an independent scanner has a deployment-salted exact-and-token fingerprint set for every authorized scalar source value
    But a served name, summary, description, warning, sample row, or value exemplar contains any ordinary raw source value, secret, or direct identifier
    When projection privacy validation runs before sealing
    Then publication fails based on the actual served content
    And a purpose-signed projection-safety receipt binds the fingerprint set and exact profile/capability hashes
    And the producer attestation cannot override any collision finding

  @FR-034-AC-02
  Scenario: require data handling on every served asset and field
    Given a profile manifest contains assets and fields
    When projection privacy validation runs
    Then every asset and field declares classification, redaction method, raw-value status, and applied minimum group size
    And missing or policy-incompatible handling prevents publication
