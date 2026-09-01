@FR-004 @FR-005 @FR-006 @FR-016 @NFR-001
Feature: Structural and statistical profiling
  The system produces reproducible, source-appropriate statistics with explicit denominators and sample receipts.

  @FR-004-AC-01
  Scenario: derive a stable structural version
    Given a source has a fixed set of assets, field paths, and physical types
    When structure is harvested twice at different times with different row counts
    Then both runs derive the same structural version
    When a field type changes
    Then the next run derives a different structural version

  Scenario: profile a small asset exactly
    Given an eligible asset population is below the exact-scan ceiling
    When statistical profiling runs
    Then every unit is inspected
    And the sample receipt marks the result exact
    And missingness, distinctness, and distributions use the full population denominator
    And every source-appropriate statistic family records passed, failed, unavailable, or not-applicable

  @FR-005-AC-02 @FR-006-AC-02
  Scenario: profile a large asset deterministically
    Given an asset population exceeds the exact-scan ceiling
    When statistical profiling runs with a deterministic seed
    Then a bounded sample is selected across configured strata
    And repeated runs with the same source version, policy, and seed select the same units
    And the receipt records population estimate, actual units inspected, method, seed, strata, and error bounds
    And sampled distinct counts are labelled approximate in the served profile

  Scenario: preserve a rare value stratum
    Given a field contains a rare but policy-safe format variant
    And uniform sampling is likely to omit it
    When stratified profiling runs
    Then the rare format is represented in type-variant evidence
    And its prevalence estimate records the rare-value sampling method

  @FR-006-AC-01 @FR-016-AC-03
  Scenario: profile null and empty assets
    Given one asset has zero rows
    And another asset has rows but one field is entirely null
    When statistics and quality are calculated
    Then the empty asset and all-null field have distinct evidence outcomes
    And no division-by-zero or non-finite score is emitted
    And unavailable quality dimensions are not replaced by an unlabeled neutral score

  @FR-005-AC-01 @NFR-001-AC-01
  Scenario: reject zero-work profiling
    Given an eligible asset has fields expected for profiling
    And the connector returns a successful response with zero actual units inspected
    When the stage gate evaluates the result
    Then the required stage fails
    And it cannot be marked completed

  @FR-016-AC-01
  Scenario: score quality at the declared granularity
    Given table-level and field-level quality checks are evaluated
    When quality evidence is stored
    Then every record declares its subject granularity
    And a table-level score cannot be consumed as a field-level score

  Scenario: detect a type variant in nested records
    Given a nested path contains strings in one stratum and numbers in another
    When the path is profiled
    Then both physical variants and their prevalence are recorded
    And no single physical type is declared authoritative without a source contract

  Scenario: distinguish requested sample size from actual work
    Given a sample plan requests one hundred thousand units
    And the connector can read only sixty thousand before a budget expires
    When evidence is written
    Then population and requested size remain metadata
    And rows inspected equals sixty thousand
    And the run is completed-partial with an explicit coverage receipt
