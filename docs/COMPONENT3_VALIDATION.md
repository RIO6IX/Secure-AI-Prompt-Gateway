# Component 3 verification record

Date: 9 September 2026  
Branch: `shaheed`  
Scope: local FastAPI security component and its existing React frontend integration.

| Check | Observed result |
|---|---|
| `python -m unittest discover -s python_gateway/tests -q` | 33 tests passed |
| `tsc --noEmit` | Passed |
| `node --test tests/rendered-html.test.mjs` | 4 checks passed |
| ESLint on changed app components and helpers | No errors; 3 dashboard warnings |
| `vinext build` | Passed; includes `/security` alongside existing routes |

The three warnings are unused `health`, unused `SettingsPanel`, and an effect dependency warning for the dashboard's polling loader. They do not affect the observed compiler/build results. The Node tests validate source wiring, not rendered browser interactions, despite their existing filename.

Backend tests create fresh temporary SQLite databases. They verify authentication, role restrictions, current identity, session expiry/revocation, mandatory credential blocks, policy validation, missing coverage, conflicting edits, policy precedence, approval lifecycle, anti-replay behavior, account controls, password upgrades, login throttling and migration of the original schema. Validation errors were checked for accidental prompt/password echo. Remote audit serialization was checked with a mocked HTTP client.

An early test run exposed unclosed SQLite connections on Windows; the shared connection helper now commits or rolls back and closes each connection. A second failure exposed a response-type mismatch when returning the numeric account-active flag; the identity response now returns the intended identity fields only. Both were corrected before the passing run.

No external AI requests, real sensitive test data, browser interaction tests, deployment, production penetration test or detector accuracy benchmark were part of these results. They must not be described as completed in the group report.

To repeat the checks on Windows after installing dependencies:

```powershell
.\scripts\verify-component3.ps1
```

The script stops on a failed stage. It performs no Git operations or deployment. Its optional `-Python` and `-Node` arguments allow explicit runtime paths.
