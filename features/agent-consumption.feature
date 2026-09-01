@FR-007 @FR-019 @FR-020 @FR-021 @NFR-007
Feature: Agent-ready manifests and hybrid intelligence retrieval
  Agents receive compact, version-scoped, policy-filtered intelligence with evidence and caveats.

  @FR-019-AC-01 @FR-031-AC-02
  Scenario: retrieve a historical manifest
    Given two source versions have different field and relationship evidence
    When an authorized caller requests the older source version
    Then the profile manifest contains only evidence compatible with that version
    And no section silently falls back to current evidence

  @FR-019-AC-02 @FR-034-AC-03
  Scenario: report incomplete manifest coverage
    Given a required structural stage completed
    And optional semantic and lineage stages were unavailable
    When the profile manifest is built
    Then it includes structural evidence
    And it names semantic and lineage as missing sections
    And dependent capabilities are emitted with validation status unavailable

  @FR-021-AC-02
  Scenario: return evidence references
    Given a manifest contains asset, relationship, quality, and business claims
    When an agent retrieves those claims
    Then every claim contains one or more evidence references
    And supporting evidence can be fetched under the same authorization scope
    And every result carries its applicable caveats or an explicit empty caveat set

  @FR-020-AC-01
  Scenario: route a question through a validated capability
    Given a capability has current assets, validated direct relationships, a validated metric contract, and acceptable quality
    When a matching question is submitted
    Then the capability is ranked for planning
    And the response identifies required assets, relationships, constraints, and evidence

  @FR-020-AC-02
  Scenario: withhold an unsupported capability
    Given a candidate capability requires a relationship that is only inferred or rejected
    When capabilities are assembled
    Then the capability is emitted with validation status unavailable
    And the missing relationship validation is reported

  Scenario: retrieve by hybrid relevance
    Given an agent question uses a business synonym rather than a physical field name
    And a reviewed glossary term maps the synonym to a concept and asset
    When hybrid retrieval runs
    Then semantic and lexical candidates are combined
    And graph expansion includes the validated asset path
    And reviewed evidence ranks above name-only hypotheses

  @FR-021-AC-01
  Scenario: apply authorization before ranking
    Given an unauthorized asset is semantically more similar than every authorized asset
    And an asset from an incompatible source version is otherwise highly ranked
    When retrieval runs
    Then unauthorized and source-version-incompatible assets are removed before scoring
    And neither leaves a count, hint, or timing disclosure in the result

  @FR-021-AC-03 @FR-035-AC-03
  Scenario: report token-budget truncation
    Given relevant intelligence exceeds the requested token budget
    When the bundle is compressed
    Then validated evidence, grain, relationships, warnings, and conflicts are preserved before weak hypotheses
    And the response reports omitted item counts by section

  @FR-035-AC-04
  Scenario: ground caveats and conflicts in evidence
    Given a retrieval result includes one caveat and one claim with counter-evidence
    When the response is assembled under a sealed projection coordinate
    Then every caveat cites resolvable evidence under that coordinate
    And each conflict cites nonempty, disjoint supporting and counter-evidence sets

  @FR-035-AC-05
  Scenario: reconcile retrieval coverage
    Given an authorized retrieval considers a known candidate set under a token budget
    When the response returns only part of that set
    Then returned and omitted item counts exactly reconcile to authorized candidates considered
    And omission counts use only the declared items, caveats, and conflicts sections
    And considered, returned, and omitted counts reconcile independently for caveats and conflicts
    And truncation and its reason agree with whether any section was omitted

  Scenario: preserve maturity separately from confidence
    Given a generated semantic hypothesis has high model confidence
    And it has not been source validated or reviewed
    When an agent retrieves it
    Then its maturity remains inferred
    And the agent cannot treat it as validated solely from confidence

  Scenario: include counter-evidence
    Given current evidence contains a high-ranked relationship hypothesis and a rejection for the same logical predicate
    When retrieval requests counter-evidence
    Then both are returned as a conflict
    And automatic query planning withholds that relationship

  Scenario: promote repeated successful usage
    Given a validated capability is used successfully by multiple independent authorized executions
    When usage evidence crosses the configured threshold
    Then its maturity becomes usage-proven
    And a new source version still requires compatibility checks before reuse

  Scenario: refuse an unsupported question
    Given an agent question requires a source capability or business metric absent from current evidence
    When planning runs
    Then no fabricated read plan is generated
    And the response identifies the missing evidence and recommended profiling or review action

  @FR-027-AC-02
  Scenario: validate and execute a typed read plan
    Given an authenticated caller retrieves a current validated capability
    And a typed read plan cites its required evidence
    When the plan is validated against caller scope, source version, policy, operations, relationships, and cost
    Then an expiring validation receipt is returned
    When the same caller executes the unchanged plan before the receipt expires
    Then only allowlisted read operations run
    And the receipt matches the caller, source version, policy, authorization scope, parameters, and resource limits
    And the requested source and manifest versions exactly match the authorized projection
    And caller-selected row, byte, duration, and text limits do not exceed deployment policy ceilings
    And the plan contains one typed operation whose result is attributable without flattening heterogeneous operations
    And the result includes a trace, complete connector/projection coordinate, and bounded execution receipt

  @FR-033-AC-01
  Scenario: withhold a foreign-scope asset
    Given a profiled source neighbours assets belonging to another authorization scope
    When a manifest is assembled and served
    Then only assets and relationship endpoints inside the caller's scope and source appear
    And no foreign asset name, field path, policy tag, or join path is disclosed

  @FR-035-AC-01 @FR-035-AC-02
  Scenario: mark source-derived response text
    Given a profile manifest, capability manifest, evidence page, retrieval result, or typed read result includes text derived from untrusted source content
    When any agent-facing response is assembled
    Then a required response policy conservatively marks unmatched text source-derived
    And explicit service-generated and source-derived path patterns are disjoint
    And every free-text field and the complete serialized body are bounded by deployment policy
    And arbitrary typed-read columns declare value provenance
    And the response carries the revocation epoch it was gated on

  @FR-027-AC-01 @FR-031-AC-03
  Scenario: complete the authenticated agent lifecycle
    Given an authenticated agent has claims granting one source scope
    When it inspects effective capabilities, resolves an immutable manifest, retrieves intelligence, validates parameters, executes the unchanged typed plan, and looks up cited evidence
    Then every response and each lexical, semantic, graph, temporal, and faceted index remains bound to the same actor, scope, source version, manifest version, policy, and revocation epoch
    When the agent submits feedback and requests run cancellation
    Then append-only feedback and cancellation receipts are retrievable without caller-controlled authority
    When an authorized lifecycle actor revokes serving and requests derived-data deletion
    Then current and historical retrieval are blocked synchronously
    And a complete per-store lifecycle receipt is retrievable after cleanup

  @FR-035-AC-05
  Scenario: refuse a stale revocation epoch during plan validation
    Given a caller presents a typed read plan for an earlier revocation epoch
    And the current source projection has a later epoch
    When plan validation recomputes the projection coordinate
    Then validation fails before a receipt can be issued
    And no source read or protected-resource existence signal is produced
