# Security Policy and Access Control Engine

Owner: H. M. Shaheed — IT23664258

Project: Secure AI Prompt Gateway — IE3092 Information Security Project

Implementation branch: `shaheed`

Revision: 9 September 2026

## 3.4 Component 3

The Security Policy and Access Control Engine determines who may use the gateway and what action is permitted after sensitive information is detected. It authenticates users, checks permissions at the API boundary, evaluates versioned policy rules, and manages approval requests. Its security objective is to prevent unauthorized prompt submission and prevent a user from bypassing a blocking decision by changing browser data, account identifiers, roles, or approval status.

This component is implemented in the existing FastAPI service in `python_gateway`. The browser supplies a bearer session token; the server obtains identity and the current role from SQLite. Content detection and initial risk scoring remain the responsibility of Components 1 and 2. Component 3 consumes those findings and produces `ALLOW`, `SANITIZE`, `BLOCK`, or `REQUIRE_APPROVAL`. Audit records retain the existing Component 4 interface, with additional security-management events stored separately for inspection.

### Authentication and session management

New passwords use salted PBKDF2-HMAC-SHA256 with 600,000 iterations. Each stored hash includes its iteration count. Existing hashes using the original 120,000-iteration format remain valid and are upgraded after successful authentication. Password comparison uses a constant-time comparison function. New and replacement passwords must contain 12–128 characters.

Successful authentication issues a cryptographically random opaque token containing 32 bytes of entropy. Only its SHA-256 hash is stored in SQLite. Sessions expire after eight hours. Every protected request joins the session record to the current user record, so account deletion or deactivation prevents subsequent access. Logout revokes the current session; password changes, administrative password resets, role changes and deactivation revoke the user's sessions.

Public registration always creates a general user. The first administrator is provisioned through a local console command, which refuses to run when an active administrator already exists. Administrators can subsequently provision accounts through the existing Admin Panel. Five failed login attempts for an account within a 15-minute window temporarily prevent further login attempts. Errors do not disclose whether an account exists, and validation responses do not echo submitted passwords or prompt content.

### Role based access control

| Operation | User | Approver | Auditor | Administrator |
|---|---|---|---|---|
| Submit a prompt to inspection | Yes | Yes | No | Yes |
| Read active policies | Yes | Yes | Yes | Yes |
| Change policies | No | No | No | Yes |
| Read approval requests | Own | All | All | All |
| Approve or reject another user's request | No | Yes | No | Yes |
| Release approved content | Own | Own | No | Own |
| Read organization audit records and export | No | No | Yes | Yes |
| Read security change history | No | No | Yes | Yes |
| Create, update, disable or delete users | No | No | No | Yes |
| Change own password | Yes | Yes | Yes | Yes |
| Reset another user's password | No | No | No | Yes |

The server rejects unknown roles and unsupported AI service names. Supported service identifiers are ChatGPT Enterprise, Google Gemini and Microsoft Copilot. These are policy targets, not evidence of implemented provider adapters. The caller's `actor` field is replaced by the authenticated account email before inspection is logged. Hiding controls in the browser is a usability measure; authorization is enforced by the API.

### Policy data and evaluation

Each rule contains an ID, name, sensitive-data category, action, applicable roles, applicable services, inclusive minimum and maximum risk scores, and enabled state. The server validates rule IDs, supported values, score boundaries and duplicate IDs. Policies are stored persistently with a version number. Updating a policy requires the version last read by the administrator; a concurrent edit returns HTTP 409 instead of overwriting newer changes.

The evaluation sequence is:

1. Authenticate the session and reject unsupported roles or providers before inspecting content.
2. Receive detector findings and the risk score computed by the existing gateway pipeline.
3. Block credentials and secrets, and block scores of 90 or higher, regardless of configurable rules.
4. Allow a prompt with no detected sensitive category.
5. Select enabled rules matching the category, current role, service and score interval.
6. Block if any sensitive category has no applicable rule.
7. Choose the most restrictive matching action: `BLOCK` before `REQUIRE_APPROVAL`, then `SANITIZE`. The rule ID provides deterministic ordering among equal actions.
8. Return the action, explanation, policy version and explicit transmission-permission flag; create an approval request when required.

| Default condition | Outcome | Transmission permitted |
|---|---|---|
| No sensitive findings | ALLOW | Yes |
| PII with applicable rule | SANITIZE | Sanitized content only |
| Financial data with applicable rule | SANITIZE | Sanitized content only |
| Source code with applicable rule | REQUIRE_APPROVAL | No, pending independent review |
| Credentials or risk score at least 90 | BLOCK | No |
| Sensitive category without a matching enabled rule | BLOCK | No |

The current interface intentionally has no warning-and-bypass action. A user cannot confirm a credential block away. Administrators may strengthen rules or require approval but cannot configure direct release of detected sensitive categories. Disabling a rule does not create an implicit allow path.

### Approval lifecycle

A pending request contains an unpredictable ID, requester ID, target service, sanitized content, policy version and an expiry time one hour in the future. Raw detected values are not retained in the approval record. An approver or administrator can approve or reject a pending request with a reason, but cannot review their own request. Auditors have read access only.

The requester releases approved content through a dedicated API endpoint. A database transaction checks ownership, current role, supported service, approved status, expiry and policy version. On success, the request becomes `CONSUMED` and its stored sanitized content is cleared. Repeated release attempts are rejected. A policy update prevents review or release under an obsolete version and requires prompt resubmission. Rejection, expiry and lack of approval also prevent release.

### Component interfaces and storage

The browser sends a prompt and target service to `/inspect`. The gateway supplies trusted identity to Component 3, runs the existing detectors and risk logic, and calls `SecurityService.evaluate`. Full replacement of detected spans provides the policy-controlled sanitized preview. This integration adapter should be replaced with Component 2's shared sanitizer when the group consolidates its implementations. Detector definitions are preserved.

The response extends the existing audit result with `decision`, `send_allowed`, `policy_version` and optional `approval_id`. A provider adapter must only use permitted content and must execute behind this server-side decision boundary. Approval release returns the stored sanitized content and bound service; it never accepts a replacement prompt from the caller.

SQLite additions are `security_sessions`, `security_login_attempts`, `security_policy`, `security_changes`, and `security_approvals`, plus an `active` column on existing users. The migration preserves user and audit data and can run repeatedly. Security-change records capture actor, time, action, target and relevant metadata for logins, policy edits, account changes and approval transitions. They are readable through a restricted endpoint. They are application-managed records, not cryptographically tamper-evident storage.

### Security threats and controls

| Threat | Implemented control | Remaining boundary |
|---|---|---|
| Browser role or actor manipulation | Identity and role obtained from server session/database | Browser XSS can still misuse a valid token |
| Use after logout, disable or deletion | Session revocation and active-user join on every request | Deployment must protect SQLite files |
| Password guessing | Salted password hashes and account-level throttling | Distributed/IP-level controls are deployment work |
| Policy weakening or concurrent overwrites | Admin-only edits, mandatory blocks, validation and version check | An administrator is trusted to manage permitted settings |
| Approval forgery or replay | Server-owned state, requester binding, expiry and atomic one-time consumption | Provider integration must honor the returned result |
| Self-approval | Requester cannot act as reviewer | Review quality depends on the assigned human |
| Sensitive content in error responses | Validation errors omit submitted input | Detector false negatives remain possible |
| Untrusted web origins | Explicit development CORS allowlist | Production must configure its own origin and TLS |

### Evaluation

The component is evaluated with automated HTTP tests using a temporary SQLite database and synthetic prompts. Tests cover protected endpoints, role separation, actor spoofing, unauthorized services, mandatory blocks, complete replacement of detected PII, policy conflicts, invalid configurations, unmatched rules, approval ownership, self-approval, expiry, replay, policy-version invalidation, account revocation, password changes, legacy password migration, throttling and database migration. Frontend validation includes TypeScript compilation, existing frontend regression checks and the production build.

No detection-accuracy or performance percentage is claimed by this component. The tests establish behavior for their specified scenarios; broader adversarial evaluation and real provider testing belong to group integration.

### Scope and limitations

This branch implements the security component and its local demonstration surface. It does not implement Sanduni's browser extension, replace Dayan and Chanuka's detector/dashboard work, or add an external AI provider call. Service names in policies do not establish those integrations. Department-based authorization, SSO/MFA, tamper-evident logging, encrypted database storage and production network controls are future work.

The existing client stores bearer tokens in browser local storage, which preserves compatibility but requires attention to XSS. Public registration, CORS origins and TLS termination must be reviewed for any deployment beyond the local university prototype. Human approval releases sanitized content only. The system cannot guarantee removal of sensitive data that its detectors fail to identify.

### Alignment with the group proposal

Use this section to replace the original brief Component 3 section and its illustrative policy table. Update the objectives to list the four implemented decisions and roles. Replace the Component 3 technology-table entry `JWT` with opaque, server-stored bearer sessions. Keep the browser extension assigned to Component 2. Describe account and role enforcement as Component 3 responsibilities and dashboard presentation as Component 4's responsibility. The alternative downloaded GLiNER/Groq backend is not automatically integrated into this Git branch; the group should reconcile its architecture before the final combined submission.
