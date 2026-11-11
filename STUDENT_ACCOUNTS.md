# Phase 15: student accounts and certificate identity

Students register at `/register` or `/student/register` with a full name,
unique username and matching password confirmation. USN Number / USN ID is
optional; an enrollment code is no longer required. Registration is disabled
unless `BLACK_FALCON_REGISTRATION_ENABLED=1` is configured before startup.
The existing `users` table and login routes are retained. New passwords use
Werkzeug's scrypt hashing; registration inserts the user and profile in one
transaction. Existing accounts, password hashes, progress, assessments and
issued certificates are preserved.

## Enable enrollment on Windows

Use the project virtual environment, because bare `py` selects Python 2.7 on
this host. Enable registration in the PowerShell terminal used to start Flask:

```powershell
if (-not $env:BLACK_FALCON_SECRET_KEY) {
    $env:BLACK_FALCON_SECRET_KEY = & .venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
}
$env:BLACK_FALCON_REGISTRATION_ENABLED = "1"
.venv\Scripts\python.exe app.py
```

This generates a session secret only if this terminal has none configured.
The secret stays in the current terminal's environment and is not printed.
For an existing deployment, load its existing secret instead. A new secret
invalidates existing login sessions, but does not change accounts or progress.

Open `http://127.0.0.1:5555/student/register`. The toggle lasts for the current
shell; configure it again in a new terminal. Unset or `0` disables registration
with HTTP 503. Set it back to `0` and restart after enrollment. Existing accounts
can still sign in when registration is disabled. On Ubuntu, put the toggle in
the protected `/etc/black-falcon.env` configuration. Anyone who can reach an
enabled registration page may attempt account creation. Keep enrollment in the
local training environment. `app.py` binds to `127.0.0.1` by default; instructors
may set `BLACK_FALCON_HOST` for a training network. The systemd service's network
bind is managed separately. The old enrollment-code environment variable is
no longer used.

Usernames contain 4 to 32 lowercase letters, digits, dots, hyphens or underscores
and begin with a letter. The server normalizes username case; duplicate and
reserved account names cannot be registered. Passwords contain 15 to 128
characters, support spaces and passphrases, and have no mandatory uppercase,
number or special-character rules. Confirmation must match exactly. A small
local blocklist rejects known common passwords; a comprehensive local blocklist
remains recommended before production. Password whitespace is preserved.
Full names contain 2 to 100
characters, support Unicode, and reject control characters and angle brackets.
Names are normalized for whitespace and stored only in `student_profiles`.
Optional USNs are trimmed, uppercased, and validated as 3 to 32 letters, digits,
hyphens or forward slashes, beginning with a letter or digit. Omitted and blank
USNs are stored as SQL NULL. Startup adds `usn` to existing profiles without
replacing records, constraints, or certificate identity locks.

## Profile and certificate rules

The authenticated `/profile` page shows only the current student's username,
full name, optional USN (or "Not provided"), UTC registration date and certificate
name. It has no editing route. USN is not added to certificates.
Name corrections require an instructor process, which is a future milestone.
The registered full name is self-declared and is not verified legal identity.

New certificates at `/soc/final/certificate` use the profile's name. Form fields
cannot override that name, account ownership, saved score, ID or date. The
existing preview and explicit issuance confirmation remain. Issuance rechecks
the exact profile name and qualifying attempt before and after conversion,
then saves the PDF and locks the profile identity in a single transaction.
A SQLite trigger prevents changing a locked profile's name or username or
clearing its lock. There is no student-facing unlock or correction operation.

Legacy accounts without profiles cannot issue new certificates. No profiles
are automatically invented from shared credentials or previous certificate
names. Previously issued PDFs remain available for the owning account, even
without a profile, and their names and bytes are never rewritten. Existing
overall and track certificate rules remain independent of the new workflow.

## Attempt limits

`auth_rate_limits` stores HMACs of identities and expiry/counter values, rather
than raw usernames, addresses, passwords or USNs. SQLite makes the
limits effective across workers, cookie resets and application restarts:

| Action | Limit per 15-minute window |
| --- | --- |
| Registration POST | 10 per peer IP address |
| Login POST | 30 per peer IP address and 10 per normalized username |

Limits count submitted attempts, including successful submissions. Exceeding
a limit returns HTTP 429 with `Retry-After`; counters expire automatically.
Config keys are `AUTH_RATE_WINDOW_SECONDS`, `REGISTRATION_RATE_LIMIT`,
`LOGIN_IP_RATE_LIMIT` and `LOGIN_USERNAME_RATE_LIMIT`. The app uses the socket
peer address and ignores untrusted forwarding headers. A later reverse-proxy
deployment must configure trusted proxy handling deliberately, especially
when many students share one address. A username limit can temporarily block
legitimate sign-in after repeated attempts; wait for the advertised interval.

## Validation

```powershell
.venv\Scripts\python.exe -m compileall -q app.py routes certificate_generator.py auth_limits.py
.venv\Scripts\python.exe audit_soc_integration.py
.venv\Scripts\python.exe validate_project.py
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

For Phase 17 Windows testing, the optional eligibility-only browser check
creates two students through registration, uses disposable databases, and
checks failing and passing seven-question assessments without invoking PDF
conversion or issuing a certificate:

```powershell
.venv\Scripts\python.exe tests/browser_certificate_smoke.py `
  --eligibility-only `
  --executable "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

Playwright is available through `requirements-browser.txt`. This Windows mode
needs no LibreOffice. The browser check enables registration only in its
disposable application and generates an ephemeral password without displaying
it. It registers students with and without a USN. Eligibility artifacts are saved
in `dist/windows-eligibility-validation`. Full conversion mode, selected by
omitting `--eligibility-only` and supplying `--soffice` if needed, is reserved
for Ubuntu deployment validation in the current milestone.

The earlier Phase 15 full-conversion check passed all 8 requested
identity/certificate checklist steps on November 7, 2026, including another
student's denied access and a byte-identical re-download after sign-in.
Original CTF progress and the legacy account were unchanged in the test.

At the earlier Phase 15 checkpoint, all 177 regression tests passed, including
15 registration tests and 17
certificate workflow tests. Compilation and validation of all 15 cases passed.
The structural audit passed 74 checks, retaining the existing BF-H-005
timestamp warning. The results are recorded in
`reports/phase15_student_identity_validation.json`.

The optional-USN registration update was validated on November 9, 2026: all
188 regression tests passed, project validation passed all 15 cases, and the
structural audit passed 74 checks with the existing BF-H-005 timestamp warning.
Chrome checks passed at 1280px, 390px and 320px widths, including both USN paths,
password visibility controls, common-password rejection, assessment eligibility
and account isolation. These checks used disposable data and did not convert or
issue PDFs. See `reports/student_registration_validation_2026-11-09.json`.

## Remaining release work

The existing training `analyst` account and its provisioning behavior are
retained for compatibility. It receives no student profile automatically and
cannot issue a new personalized assessment certificate without one. Do not
assign a shared account a student's profile. Replace known training-account
provisioning with instructor-controlled provisioning before distributing the
OVA; do not overwrite existing learners' passwords during that work. Instructor
name-correction tools, Ubuntu rendering/deployment validation, issuing-authority
approval and the existing BF-H-005 timestamp review remain release tasks.

## Phase 16: release password preparation utility

`prepare_release_accounts.py` is ready for later use and has **not been run**
against the development or release database. The current shared password is
unchanged. The script was syntax-checked only; regression tests simulate a
rotated password exclusively in a disposable database and verify that startup
preserves it alongside other students and CTF progress.

After final browser testing, stop the service and back up the intended release
database. Run the utility manually against that existing database:

```powershell
.venv\Scripts\python.exe prepare_release_accounts.py --database "PATH_TO_FINAL_RELEASE_DATABASE"
```

Without `--database`, it uses `Config.DATABASE_PATH`. It displays the resolved
path and requires the exact confirmation `yes`. Cancellation, a missing
database or a missing analyst account makes no account changes. The utility
never initializes or recreates accounts. It updates only the existing analyst
password hash, using a random credential, and displays the new password after
the transaction commits. Store it privately and avoid terminal transcripts.
Other students, roles, profiles, progress and certificates are preserved.

Default-account provisioning skips existing accounts, so subsequent startup
does not restore the known password after rotation. Removing development
credential hints and completing instructor-controlled provisioning remain
release checks. The sample PDF and template verification commands are in
[CERTIFICATES.md](CERTIFICATES.md).
