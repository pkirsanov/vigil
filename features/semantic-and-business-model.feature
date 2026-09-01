@FR-008 @FR-009 @FR-017
Feature: Semantic and business-model extraction
  The system converts bounded evidence into structured hypotheses without inventing source structure or claiming generated truth.

  @FR-008-AC-01
  Scenario: extract structured semantics
    Given an evidence pack contains exact field paths, physical types, statistics, and redacted value shapes
    And the evidence is sufficient to classify every requested field
    When semantic extraction runs
    Then every requested field receives a structured response
    And asset purpose, field roles, identity hypotheses, grain hypotheses, freshness behavior, and quality concerns cite input evidence
    And all output maturity states are inferred

  @FR-008-AC-02
  Scenario: reject invented field references
    Given a generated response names a field path absent from harvested structure
    When the response is validated
    Then the invented reference is rejected
    And it is counted in hallucinated-path telemetry
    And no evidence record or manifest contains the invented path

  @FR-008-AC-03
  Scenario: recover from malformed generated output
    Given a live semantic response is wrapped in prose and does not validate against the output schema
    When the parser rejects it
    Then exactly one corrective retry requests contract-compliant JSON
    And a successful retry is stored with retry provenance
    And a second invalid response produces unavailable semantic evidence rather than fabricated defaults

  @FR-009-AC-01
  Scenario: recover structured identity from narrative
    Given generated narrative names two exact harvested fields as an identity alternative
    And the structured identity array is empty
    When the deterministic fallback parses the narrative
    Then it emits separate lower-confidence identity hypotheses for each alternative
    And it does not mark either identity validated

  @FR-009-AC-02
  Scenario: do not recover an unknown field
    Given generated narrative names a token that is not an exact harvested field path
    When deterministic fallback runs
    Then the token is ignored
    And no identity is emitted from that token

  Scenario: reconcile domains holistically
    Given per-asset semantic extraction assigned inconsistent domains to related assets
    When holistic domain reconciliation sees all assets, identities, purposes, and validated relationships
    Then it emits candidate domain assignments with alternatives and evidence
    And an isolated asset is not forced into a new domain solely from its name

  @FR-017-AC-01
  Scenario: derive a business entity and event
    Given one validated identity represents a durable entity
    And an event-grain asset references that identity and has validated event time
    When business-model synthesis runs
    Then it emits separate entity and event hypotheses
    And each cites the supporting identity, grain, temporal, and relationship evidence
      And every concept family has a typed contract and all concept, asset, relationship, measure, dimension, metric, and evidence references resolve
      And metric and measure calculations use a closed expression tree with explicit grain, population, time, missing-data, freshness, and quality semantics
      And storage, hierarchy, graph, dimensional, and temporal model patterns are published separately with maturity, alternatives, and conflicts

  @FR-017-AC-02
  Scenario: derive a metric contract
    Given a validated measure, dimension, time field, grain, and relationship path support a business question
    And no validated evidence identifies the measure unit
    When metric synthesis runs
    Then it emits a metric hypothesis with a null unit and an unknown-unit constraint
    And it records formula, numerator, denominator, grain, time semantics, filters, missing-data semantics, and dependencies
    And the metric remains a hypothesis until parsed, type-checked, dry-run, and fixture-validated

  @FR-017-AC-03
  Scenario: keep scenario relationships provisional
    Given a business scenario requires two assets to connect
    And no validated direct relationship exists
    When the scenario is published
    Then the required relationship is marked a hypothesis
    And it is submitted to relationship validation
    And no capability requiring it is advertised as validated

  Scenario: generated semantics are unavailable
    Given the semantic provider is unavailable
    When deterministic profiling completes
    Then structural and statistical evidence remains publishable
    And semantic sections are explicitly unavailable
    And dependent business capabilities are withheld
