# Shaheed's Component 3 demonstration and handoff

## Start the existing project

Run from the repository root. Use Python 3.11 or newer and Node.js 22.13 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r python_gateway/requirements.txt
.\.venv\Scripts\python.exe -m python_gateway.bootstrap_admin
.\.venv\Scripts\python.exe -m uvicorn python_gateway.app:app --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
npm ci
npm run dev
```

For a disposable local demonstration database, you may replace the interactive administrator bootstrap with:

```powershell
.\.venv\Scripts\python.exe -m python_gateway.setup_demo
```

This command works only when the local database has no accounts. It creates synthetic administrator, user, approver and auditor identities, generates a random password, and writes the credentials to the Git-ignored `.local-demo/credentials.txt`. It refuses to modify a database that already contains users. Never reuse these accounts or their shared demonstration password outside local testing.

Open the local frontend URL printed by the development server. Sign in with the administrator you created. Existing databases retain their accounts; the bootstrap command refuses to create another initial admin. Existing users must sign in again because the old self-contained tokens have been replaced.

No accounts or credentials are committed. The application database and virtual environment are ignored by Git. Before using an existing group database, stop the backend and make a backup copy of `python_gateway/audit_logs.sqlite3` outside version control. The additive migration runs automatically at startup.

## Suggested demonstration

1. As administrator, use Admin Panel to create a user, approver and auditor with synthetic email addresses and passwords, or use the disposable setup command above. Use separate browser profiles or sign out between identities.
2. As user, open Security Controls and inspect `Explain least privilege`. Expect `ALLOW`.
3. Inspect `Contact fictional.person@example.test for details`. Expect `SANITIZE`, with the email fully replaced by `[REDACTED]`.
4. Inspect `password=FictionalPass123!`. Expect `BLOCK`, no outbound content and no permission to send.
5. Inspect `const internalCustomerRecords = confidentialRecords;`. Expect `REQUIRE_APPROVAL` and a pending record.
6. As approver, open Security Controls, enter a review reason and approve that request. Only sanitized content is shown. Self-approval is prohibited.
7. As the requester, refresh and release approved content once. It appears as permitted sanitized output, without an AI provider call. A second release fails.
8. Create another approval, then change a policy as administrator. The old approval cannot release content under the new policy version.
9. Disable the PII rule and submit an email. Expect `BLOCK` because a sensitive category without a matching rule does not default to allow. Restore the rule afterward.
10. As auditor, read audit records. An attempt to create accounts, submit a prompt, or edit a policy returns HTTP 403.
11. Disable the test user or change their role while their other browser session is open. Their next protected request must require a new login.
12. Change your own password in Security Controls. All your sessions are revoked; sign in using the new password.

Capture your own screenshots of each result and record the date and test identity in your logbook. The screenshots from the downloaded backend are not evidence of this branch's new controls. Do not claim fabricated dates, commits, authorship history, accuracy percentages or provider submissions.

## Automated verification

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s python_gateway/tests -v
npx tsc --noEmit
node --test tests/rendered-html.test.mjs
npm run build
```

The backend suite uses temporary databases, never the working account database, and does not send test prompts to AI providers. A mocked HTTP client checks that the remote audit request excludes `originalPrompt`. The Node tests check the existing frontend wiring; they are not browser interaction tests.

## Integration contract for teammates

| Interface | Permission and purpose |
|---|---|
| `POST /auth/register` | Public; creates a user only |
| `POST /auth/login` | Public; authenticates and returns the existing `token`/`user` response shape |
| `GET /auth/me` | Valid session; trusted ID, email, name and current role |
| `POST /auth/logout` | Valid session; revokes the supplied token |
| `POST /auth/password` | Valid session plus current password; changes password and revokes sessions |
| `POST /admin/users` | Admin; provisions an account, without issuing its login token |
| `PATCH /admin/users/{id}` | Admin; body `{role, active}`; revokes that user's sessions |
| `POST /admin/users/{id}/password` | Admin; body `{new_password}`; resets another user's password and revokes sessions |
| `DELETE /admin/users/{id}` | Admin; deletes another account and its sessions |
| `GET /security/policy` | Authenticated; complete policy plus version |
| `PUT /security/policy` | Admin; `{expected_version, rules}`; HTTP 409 for stale edits |
| `GET /policies` | Existing dashboard-compatible view of live rules |
| `POST /inspect` | User/admin/approver; existing prompt/service request; actor is replaced from session |
| `GET /security/approvals` | User sees own; admin/approver/auditor see all |
| `POST /security/approvals/{id}/decision` | Admin/approver, not requester; `{decision: APPROVED or REJECTED, reason}` |
| `POST /security/approvals/{id}/consume` | Requester; valid approved version, not expired or consumed |
| `GET /security/changes` | Admin/auditor; security-management history |
| Existing audit summary, events and export | Admin/auditor only |

Prompt decision responses contain `decision`, `send_allowed`, `policy_version`, `approval_id`, `maskedOutput` and the existing audit fields. A blocked result has an empty `maskedOutput`; a pending result must not be sent. Approval consumption returns `sanitized_prompt` and the service bound to that approval. Provider adapters must live behind the backend security boundary. Neither browser visibility nor a client-supplied decision is authorization.

The rule editor supports action, inclusive score limits and enabled state. The policy API also supports role/service lists and replacement of the full rule set. Removing coverage causes a block. Credentials and scores >=90 remain blocked even if configurable rules are removed.

## Compatibility and deployment notes

- The migration adds security tables and `users.active`; it preserves existing audit rows and accounts and normalizes the pre-existing legacy administrator labels.
- The `admin`, `auditor` and `user` names remain; `approver` is added. General users now submit prompts in `/security` rather than read organization audit data.
- Existing passwords still work. Successful login upgrades their stored format. Old tokens require a fresh login.
- The frontend uses the existing `NEXT_PUBLIC_API_BASE_URL` default of `http://localhost:8000`. Backend `CORS_ORIGINS` defaults to localhost/127.0.0.1 on ports 3000 and 5173. Configure it for another frontend origin.
- Remote audit remains optional. No AI provider adapter, extension interception, GLiNER model, department rules or production hosting is added by this component.
- Session tokens remain in browser local storage for compatibility. Production deployment should evaluate an HTTP-only cookie/BFF design alongside CSRF controls and TLS.
- Restoring the old code alone does not restore its token behavior. Back up the database before a group integration or rollback.

## Viva preparation

Be ready to explain authentication versus authorization; why a bearer token is hashed at rest; why roles come from the database; why a removed rule blocks; why credential blocks cannot be weakened; how policy versions prevent stale updates; and how a transaction prevents approval replay. Explain the detector limitations honestly and distinguish inspection from an actual external AI request.

Your reviewable proposal source is in `docs/COMPONENT3_PROPOSAL.md`; the generated submission copy is `docs/Shaheed_Component3_Proposal.docx`. Rebuild it with `python scripts/build_component3_proposal.py` after changing the source. Both are kept inside your branch, and the original group Word document outside the repository is unchanged.
