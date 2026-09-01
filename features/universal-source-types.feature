@FR-025
Feature: Universal source-type profiling
  Source-specific profilers emit common evidence while respecting native structure and validation semantics.

  Scenario: profile a tabular file collection
    Given a collection contains delimited and columnar files with partitions
    When the file connector profiles the collection
    Then it infers columns, physical types, partition keys, schema variants, and file-level lineage
    And every statistic records the files and rows represented

  Scenario: profile a polymorphic nested field
    Given a nested record path contains multiple object shapes and array item types
    When nested profiling runs
    Then each path and variant is recorded with prevalence
    And a path absent from a bounded sample is not declared absent from the collection

  Scenario: profile a document corpus
    Given an authorized corpus contains documents with sections, references, and instruction-like text
    When document profiling runs
    Then documents are sampled across format, size, language, age, and scope
    And sections, chunks, topics, claims, entity mentions, and references are inferred as evidence
    And instruction-like content cannot change profiler tools or policy

  Scenario: validate a document citation
    Given a document contains a citation to another asset
    When reference validation runs
    Then the connector resolves the target within authorization scope
    And a successful resolution creates validated citation evidence
    And a transport failure creates unavailable evidence rather than a rejected citation

  Scenario: profile an api contract
    Given an authorized API publishes a machine-readable contract
    When API profiling runs
    Then operations, parameters, response paths, errors, pagination, and declared references are observed
    And bounded sample calls verify response-shape variants and operational limits
    And no state-changing operation is invoked

  Scenario: profile an api without a contract
    Given an authorized API has no machine-readable contract
    And policy permits bounded safe sample calls
    When API profiling runs
    Then response paths and variants are marked inferred from sampled observations
    And unsupported pagination or rate-limit behavior remains unavailable

  Scenario: profile an event stream
    Given a stream contains partitions, event types, correlation keys, late arrivals, and state changes
    When stream profiling runs across bounded time windows
    Then it records event schemas, variants, throughput, inter-arrival distributions, ordering, duplication, and transitions
    And correlation relationships include temporal alignment evidence

  Scenario: profile a graph
    Given a property graph exposes node labels, edge types, directions, and properties
    When graph profiling runs
    Then node and edge schemas, degree distributions, native constraints, and common bounded paths are observed
    And native edges remain distinct from semantically inferred links

  Scenario: profile multimodal assets
    Given an authorized collection contains media with metadata, transcripts, optical text, and timestamps
    When multimodal profiling runs
    Then each derived transcript, text region, frame segment, and embedding retains provenance to the media asset
    And cross-modal links require shared identifiers, temporal alignment, or reviewed semantic evidence

  @FR-025-AC-02
  Scenario: unsupported source semantics remain unavailable
    Given a custom connector can enumerate assets but declares no content or aggregate capability
    When the common pipeline runs
    Then it publishes structural evidence only
    And statistical, semantic, and relationship sections are unavailable rather than copied from generic defaults

  @FR-025-AC-01
  Scenario: reconcile source-kind stage and validator declarations
    Given every registered source kind declares supported, conditional, and unavailable stages
    And each source kind declares the validators appropriate to its native semantics
    When the source-kind registry is validated against the canonical pipeline and taxonomy
    Then every canonical stage is accounted for exactly once for that source kind
    And every declared validator is registered for that source kind

  @FR-025-AC-03
  Scenario: publish a signed source extension
    Given a source adapter emits a source-specific aggregate payload for an existing asset
    When the profile manifest is sealed
    Then the extension uses a closed payload kind and schema
    And its source, version, scope, policy, epoch, asset, and evidence references resolve inside the manifest coordinate
    And a trusted redaction receipt signs the payload kind, payload hash, classification, and handling decision

  @FR-028-AC-02
  Scenario: reject a malformed or expanding file
    Given a file has mismatched declared and detected media types or expands beyond the decode budget
    When isolated file parsing runs
    Then content parsing is blocked
    And structural failure evidence records the reason without retaining the content

  Scenario: preserve partial api pagination
    Given an API returns two authorized pages and then rate limits further pages
    When response profiling reaches the call budget
    Then inspected pages and the continuation state are recorded
    And population-level statistics remain partial
    And no missing later path is declared absent

  Scenario: handle an expired stream offset
    Given a resumed stream profile references an offset that is no longer retained
    When the connector attempts to establish the old boundary
    Then the boundary is marked expired
    And a new run is required without combining old and current windows

  Scenario: isolate an unauthorized graph neighbor
    Given an authorized node has a native edge to a node outside caller scope
    When graph profiling traverses the edge
    Then the unauthorized node and its properties are not disclosed
    And the visible graph records a policy-filtered boundary without identifying the hidden node

  Scenario: preserve unavailable document parsing
    Given an encrypted document cannot be parsed under the approved parser policy
    When document profiling runs
    Then its content stage is unavailable
    And metadata permitted by policy remains separately observed

  @FR-028-AC-03
  Scenario: bound hostile media processing
    Given a media asset exceeds duration, frame, transcription, or optical-text budgets
    When isolated media profiling runs
    Then processing stops at the configured bounds
    And derived segments report partial coverage
    And no unprocessed interval is described as analyzed

  @FR-028-AC-01
  Scenario: isolate hostile parser execution
    Given an untrusted document, archive, image, audio, or video requires parsing
    When parser execution starts
    Then it runs in a credential-free worker with no outbound network or external-reference resolution
    And input is read-only, output is disposable, and CPU, memory, expansion, recursion, file-count, duration, frame, and output limits apply
    And a versioned parser receipt records detected media type, coverage, resource use, outcome, and cleanup

  @FR-028-AC-04
  Scenario: record a failed parser cleanup
    Given an isolated parser worker is terminated for breaching a declared resource limit
    When teardown cannot remove its decoded output
    Then the receipt records cleanup as incomplete with a reason code and a nonzero residual artifact count
    And the outcome is partial, blocked, failed, or cancelled rather than completed

  @FR-036-AC-01
  Scenario: reject a parser receipt with self-inflated ceilings
    Given a parser receipt declares one or more resource ceilings above the governing isolation policy
    When receipt validation compares every ceiling with the policy version it names
    Then the receipt is rejected even when observed usage stays below its self-declared limits
    And no completed parser outcome can be published from that receipt
