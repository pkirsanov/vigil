@FR-001 @FR-002 @FR-003 @FR-004
Feature: Source onboarding and durable profiling runs
  The system registers an authorized source, negotiates its capabilities, and records profiling state before work begins.

  Scenario: register an authorized source
    Given a valid source descriptor containing only a credential reference
    And the caller is authorized to enumerate and read the source
    When the caller registers the source
    Then a stable source identifier is returned
    And a pending profiling run is durably recorded before source profiling starts
    And the run records the source version candidate and policy hash
     And the resolved connector implementation version and canonical capability hash are pinned

  @FR-001-AC-02
  Scenario: reject embedded credentials
    Given a source descriptor contains secret material instead of a credential reference
    When the caller registers the source
    Then registration fails before any connector call
    And no secret material is written to logs or evidence

  @FR-030-AC-01 @FR-030-AC-04
  Scenario: reject secrets hidden in allowed registration fields
    Given a token or connection string is placed in a display name, locator, tag, policy reference, or credential reference
    When whole-request secret detection runs
    Then registration fails with a non-echoing reason code
    And no caller-provided string is persisted or logged
    And no caller-provided string is echoed in an error response

  @FR-030-AC-02
  Scenario: reject an unlabelled high-entropy credential
    Given a caller-controlled registration field contains an unlabelled opaque value from a recognized credential family or with credential-like entropy
    And a benign opaque source identifier is present as a control
    When whole-request secret detection runs
    Then the credential-like value is rejected with a non-echoing reason code
    And the benign source identifier is not classified as secret material

  @FR-030-AC-03
  Scenario: reject a locator authority escape
    Given a source locator contains an absolute URI, IP literal, parent traversal, encoded separator, backslash, user information, query, fragment, or redirect outside its registered endpoint
    When endpoint resolution and canonicalization run
    Then registration or connector invocation fails before network access
    And the response does not disclose endpoint registry contents

  @FR-001-AC-01
  Scenario: negotiate an unsupported capability
    Given a connector can enumerate structure but cannot sample content
    And the selected policy requires statistical evidence for publication
    When the profiling plan is created
    Then structural discovery is applicable
    And statistical profiling is marked unavailable
    And the run does not report statistical profiling as completed

  Scenario: reject an unauthorized source
    Given the caller has no entitlement to the source
    When the caller registers or inspects the source
    Then the operation is denied before enumeration
    And the response does not reveal whether assets exist

  @FR-003-AC-01 @FR-014-AC-03
  Scenario: resume an interrupted run
    Given a run persisted completed work through the structural stage
    And the process terminated during statistical profiling
    When a resume run is requested
    Then a purpose-signed checkpoint resolves an immutable predecessor summary and exact completed stage/receipt set
    And completed structural evidence is reused only when its source, scope, connector, policy, method, taxonomy, and revocation coordinates remain compatible
    And its source boundary remains unexpired
    And pending statistical work is reclaimed under a newly acquired lease and fencing token
    And no duplicate logical evidence is produced

  @FR-003-AC-03
  Scenario: acquire and release a fenced run lease
    Given accepted work has a durable pending run before any worker owns it
    Then the pending run has no lease, execution start, or fencing token
    When a worker acquires the source lease
    Then the running run carries the same unexpired lease token at its observation time
    When the run reaches a terminal state
    Then the lease is released and the final fencing token remains in the immutable run and evidence records

  @FR-003-AC-02
  Scenario: reprofile a terminal source run
    Given a previous run is completed or failed
    When a manual reprofile is requested
    Then a new pending run is created
    And the completed or failed predecessor remains immutable
    And the new run records the prior run as its predecessor

  @FR-036-AC-03
  Scenario: concurrent registration of the same source
    Given one profiling run owns a valid source lease and fencing token
    And contention policy queues one compatible successor run
    When another worker tries to start incompatible work for the same source version
    Then the second worker is queued without starting source work
    And an expired lease holder cannot publish evidence with an older fencing token

  @FR-003-AC-03
  Scenario: resolve typed terminal stage receipts
    Given every terminal stage cites one typed receipt identifier and receipt type
    When the run ledger is validated
    Then each reference resolves to the same run, stage, attempt, method, outcome, completion time, and exact work accounting
     And each signed receipt resolves dependency receipts and output artifact byte hashes under the same connector, scope, policy, epoch, and fencing coordinate
     And an unresolvable, wrong-type, stale-coordinate, output-mismatched, or unreferenced receipt fails the run contract

  @FR-026-AC-01
  Scenario: profile within a stable source boundary
    Given the connector opens a stable snapshot token before structural discovery
    When every source-reading stage reads through that snapshot
    And boundary verification runs after every evidence-producing stage terminates
    Then the terminal run records the opening and verification times for the snapshot boundary
    And all published evidence is bound to one source version

  @FR-026-AC-02
  Scenario: detect source change during profiling
    Given the connector cannot provide a snapshot
    And the source structure or watermark changes between the before and after checks
    And policy requires consistency for current-manifest publication
    When the run reaches projection publication
    Then consistency status is changed-during-run
    And the run fails publication
    And no coherent current manifest is published from the mixed observations

  @FR-026-AC-03
  Scenario: handle an unavailable consistency boundary
    Given the connector has no snapshot or watermark capability
    And policy permits best-effort structural discovery only
    When profiling runs with a before-and-after check that cannot establish consistency
    Then consistency status is unavailable
    And only explicitly partial structural evidence is published
    And data-query capabilities are withheld

  @FR-026-AC-03
  Scenario: reject an expired resume boundary
    Given an interrupted run used a watermark that is no longer retained by the source
    When resume is requested
    Then the old boundary is marked expired
    And the run cannot append evidence under the old source version
    And a new profiling run is required

  @FR-036-AC-02
  Scenario: hold and release the per-source run lease
    Given a profiling run is in the running state
    When its per-source lease and fencing token are inspected
    Then the running run has one unexpired lease bound to its fencing token
    When the run reaches any terminal state
    Then the terminal run has released the lease without removing its recorded fencing token
