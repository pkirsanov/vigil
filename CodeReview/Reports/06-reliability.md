# Reliability Review

## Current Verdict

**RESOLVED — the reported verifier-substitution attack is rejected by the current package.**

The historical finding below applied before the validation entrypoints authenticated
the package-local validation-control verifier against an independently supplied byte
pin. The current entrypoints hash `scripts/validation_control.py` with Python's
standard library before importing it. Production mode requires the caller to provide
that verifier hash together with the external issuer-registry and validation-control
hashes.

The regression
`test_runner_rejects_replaced_verifier_and_191_vacuous_tests_with_original_external_pins`
replaces both the verifier and the signed test suite while retaining the caller's
original pins. It now confirms that the runner exits nonzero before accepting the
replacement suite. The canonical package validator reports 32 passing gates and
13,062 checks, and the signed test runner reports 194 passing tests.

This remediation does not make an entrypoint self-authenticating. As documented in
the package README, production still requires an immutable external launcher or
policy engine that pins the exact entrypoint bytes before execution. That external
bootstrap remains the deployment root of trust.

## Historical Finding

### Original Verdict

**FAIL — one reproducible P1 reliability defect.**

The package-local validation-control verifier is loaded before the externally pinned validation control is authenticated. Replacing that verifier and the signed test suite allows 191 vacuous tests to report `PASS PRODUCTION` while the caller continues to supply the original external registry hash and original validation-control byte hash.

## 1. Test Documentation Quality

The focused test names generally describe scenario and expected behavior well. The existing dynamic-verifier test documents only that the ordinary import resolves to the package-local verifier; it does not specify that production trust must authenticate that executable verifier.

## 2. Coverage Map

| Reliability decision | Existing coverage | Reproduction result | Status |
|---|---|---|---|
| Reject vacuous replacement of the signed suite | Signed test-file byte pins; focused replacement test | Replacement alone is rejected | Covered |
| Reject skipped tests | Runner checks `result.skipped` | Resealed one-test skipped suite exits nonzero and reports the skip | Covered |
| Reject no-tests execution | Runner checks discovered count against a positive floor | Resealed empty suite exits nonzero and reports 0 discovered | Covered |
| Reject signed test byte mutation | Exact SHA-256 test-file pins | Mutation rejected | Covered |
| Reject governed prompt byte mutation | Exact SHA-256 prompt-file pins | Mutation rejected | Covered |
| Prevent child-process bytecode/cache artifacts | Runner sets interpreter and environment bytecode suppression | Scratch child-process runs produced zero cache artifacts | Covered for observed invocation |
| Authenticate production validation-control implementation | No executable pin or external verifier | Package-local verifier replacement bypassed all foreign pins and accepted 191 vacuous tests | **P1 gap** |

## 3. Assertion & Isolation Quality

Focused mutation tests use isolated temporary package copies and assert externally visible failure outcomes. The skip/no-test tests correctly distinguish `skipped`, `discovered`, and `executed` states.

The trust-boundary test is insufficient: asserting the source path of loaded functions is an implementation-location assertion, not proof that the verifier bytes are trusted. The process entry point imports executable verification logic from the mutable package before authenticating any externally pinned material.

## 4. Severity Ratings

### P1 — Production validation can be bypassed by replacing the package-local verifier

**Reproduction:**

1. Copy the exact package to a temporary directory.
2. Replace the test module with 191 tests that only assert true.
3. Replace the package-local validation-control module with a loader returning that test path and a minimum count of 191.
4. Invoke the production runner with an external production registry and the SHA-256 pin of the original, unchanged validation-control document.
5. Result: exit code `0`, `PASS PRODUCTION: 191 tests executed`, 191 vacuous tests passed, and zero bytecode/cache artifacts.

This defeats the suite pin, prompt pins, minimum count, signature checks, registry hash pin, and independent control byte pin because the mutable verifier is trusted to enforce all of them.

## 5. Recommendations

1. Move production verification of the validation-control document into a verifier supplied outside the package trust boundary, or independently pin and authenticate the exact verifier/runner bytes before executing them.
2. Add a process-level regression test that replaces the package-local verifier and test suite while retaining the caller's original foreign pins; production mode must exit nonzero before loading tests.
3. Keep the existing vacuous-suite, skipped-test, zero-test, signed-byte-mutation, and cache checks; those behaved fail-closed when the verifier itself remained trusted.
