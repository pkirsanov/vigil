@FR-010 @FR-011 @FR-012 @FR-013 @FR-014 @FR-015
Feature: Identity, grain, relationship validation, and graph paths
  The system generates broad hypotheses but promotes only source-supported relationships.

  @FR-010-AC-01
  Scenario: validate a scoped identity
    Given a local identifier repeats across two scopes
    And the composite of scope and local identifier is complete and unique
    When identity validation runs
    Then the local identifier alone is rejected as a global identity
    And the scoped composite is validated as entity identity
    And its stable logical key stores ordered scope, local-key, and version paths with a canonical sample-plan hash

  @FR-010-AC-02
  Scenario: distinguish entity identity from versioned row grain
    Given an entity identifier repeats across versions
    And a version sequence makes each row unique
    When identity and grain are inferred
    Then entity identity excludes the version path
    And row grain includes entity identity and version path

  @FR-010-AC-03
  Scenario: preserve unavailable identity validation
    Given exact identity validation exceeds its resource budget
    And a bounded sample finds no duplicate but does not cover the population
    When validation finishes
    Then the candidate remains unavailable
    And it is not marked validated

  @FR-011-AC-01
  Scenario: merge duplicate hypotheses
    Given name, semantic, value-overlap, and usage strategies identify the same endpoint pair
    When candidates are assembled
    Then one candidate remains
    And it records every independent discovery technique

  @FR-011-AC-02
  Scenario: do not generate blind cross-products
    Given many identifier-like fields share compatible types but no name, semantic, value, constraint, lineage, or usage signal
    When candidate generation runs
    Then those pairs are not generated

  @FR-012-AC-03
  Scenario: validate a composite relationship
    Given two assets have aligned scope and local-key paths
    And all composite components are present
    When relationship validation runs
    Then normalization is applied per component
    And overlap is measured on the complete tuple
    And the evidence records bilateral coverage, cardinality, matches, validation method, sample receipt, and all predicates
    And the served relationship copies every decision-bearing join field and recommended operation from that evidence

  @FR-012-AC-01
  Scenario: reject a plausible relationship with zero overlap
    Given two fields have identical names and compatible types
    But exact distinct validation finds no matching key
    When relationship validation completes
    Then the candidate is rejected for the pinned source version
    And the profiling run completes with the relationship recorded as rejected

  @FR-012-AC-02
  Scenario: preserve validator unavailability
    Given a relationship validation probe times out before evaluating keys
    When the validator records its outcome
    Then the candidate is unavailable
    And it is not recorded as a zero-match rejection

  @FR-013-AC-01
  Scenario: validate a sparse key population
    Given a relationship key is populated in a small fraction of rows
    When the validator selects a sample plan
    Then it filters eligible non-empty keys before deterministic hash bucketing
    And a random sample miss cannot produce false zero-distinct evidence

  @FR-013-AC-02
  Scenario: validate a high-cardinality relationship
    Given two large key spaces have a real reference relationship
    And the smaller side is within the exact distinct-key budget
    When validation runs
    Then it does not independently sample both sides
    And it enumerates the smaller side and probes the other side

  Scenario: treat top-value overlap as supporting evidence
    Given two high-cardinality fields have no shared top values
    But their long-tail key sets overlap
    When candidate validation runs
    Then top-value absence does not reject a high-evidence candidate
    And source overlap determines the result

  @FR-014-AC-01 @NFR-003-AC-02
  Scenario: defer weak hypotheses durably
    Given many low-evidence candidates remain after the inline gate
    When foreground validation completes
    Then remaining candidates are stored in a durable restart-safe queue
    And the foreground run reports deferred counts and coverage

  @FR-014-AC-03
  Scenario: reuse prior validation safely
    Given a relationship was validated for the same source version, policy, predicate, normalization, and validator version
    When a later incremental run generates the same candidate
    Then prior evidence is reused
    When any compatibility key changes
    Then the candidate is revalidated

  @FR-014-AC-02
  Scenario: reclaim deferred relationship candidates after restart
    Given weak relationship candidates were persisted to the durable validation queue
    And the profiling worker terminates before processing them
    When a compatible worker resumes the run from its durable checkpoint
    Then the deferred candidates are reclaimed without changing their stable deduplication keys
    And no candidate is lost or processed twice as a logical effect

  @FR-012-AC-04 @FR-033-AC-03
  Scenario: reject an unauthorized cross-scope relationship
    Given a candidate relationship whose endpoints carry different authorization scopes
    And no explicit cross-scope authorization grant exists for the run
    When relationship validation runs
    Then the candidate is not validated
    And no cross-scope evidence, index entry, or capability is published

  @FR-015-AC-02 @FR-015-AC-03
  Scenario: infer a path from trusted edges
    Given two direct edges are validated and use the same compatible intermediate key
    When path discovery runs within the hop limit
    Then it emits an inferred path with hop penalty and weakest-edge sensitivity
    And the path reports no direct matching rows

  @FR-015-AC-01
  Scenario: block path expansion from an untrusted edge
    Given one edge is only an unvalidated semantic hypothesis
    When graph path discovery runs
    Then that edge cannot seed an inferred path

  @FR-033-AC-02
  Scenario: derive the cross-scope indicator from endpoint scopes
    Given a relationship payload declares endpoint authorization scopes
    When relationship validation recomputes whether those scopes differ
    Then the derived cross-scope indicator must equal the payload indicator
    And a mismatch is rejected before evidence or projection publication
