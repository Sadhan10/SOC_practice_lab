# Windows validation

Latest validation date: 2026-11-09 (Asia/Calcutta).

## Optional USN registration update

The current registration page uses a centered card with a maximum width of
560px, optional USN Number / USN ID, and matching 15 to 128 character passwords.
Passphrases and spaces are supported without mandatory uppercase letters,
numbers or symbols. A basic local blocklist rejects known common passwords.
USN appears only in the student's profile; certificate names and templates
retain their existing behavior.

Registration is disabled by default. For manual enrollment in the local
training environment, use the same PowerShell terminal to enable it and start
Flask with the project Python 3 environment:

```powershell
if (-not $env:BLACK_FALCON_SECRET_KEY) {
    $env:BLACK_FALCON_SECRET_KEY = & .venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
}
$env:BLACK_FALCON_REGISTRATION_ENABLED = "1"
.venv\Scripts\python.exe app.py
```

The generated session secret lasts for this terminal. For an existing
deployment, load its existing secret instead; changing it signs users out
without changing accounts or saved progress.

Open `http://127.0.0.1:5555/student/register`. Set the toggle to `0` and restart
after enrollment. No enrollment code is required. See
[STUDENT_ACCOUNTS.md](STUDENT_ACCOUNTS.md) for the migration, validation results
and registration limits.

## Phase 17: final Windows integration and certificate eligibility

Verified with the project Python 3.12.4 virtual environment:

- Syntax compilation passed for the app, routes, tests and certificate generator.
- Complete regression suite: **182 tests passed**. Certificate conversion is
  mocked in these tests; no installed PDF converter is required for the suite.
- Project validator: all 15 cases passed, zero errors and zero warnings.
- Structural integration audit: **74 checks**, zero errors and the existing
  BF-H-005 chronology warning. The audit exits 0; strict release readiness
  still requires review of that warning.
- Real headless Chrome registration/eligibility workflow passed using two
  students, ephemeral credentials and disposable main/feature databases.
- Original BF-H-005 evidence: all seven file hashes match the recorded
  reconciliation manifest. Wazuh/Suricata remain the graded chronology sources.

The eligibility browser check verified registration, profile isolation,
assessment ownership, a locked certificate after 64/100, a profile-name preview
after 74/100, rejection of forged marks and another account's requests, and
eligibility after logout/login. It left existing CTF progress and the legacy
account unchanged. **PDF conversion calls: 0. Issued certificate records: 0.**
It did not click Confirm and Issue Certificate. Actual PDF conversion and
issuance validation are deferred to Ubuntu for this milestone. The release
password-rotation utility was not run.

Reproduce this stage from the project root:

```powershell
.venv\Scripts\python.exe -m compileall -q app.py routes tests certificate_generator.py
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe validate_project.py
.venv\Scripts\python.exe audit_soc_integration.py
.venv\Scripts\python.exe tests\browser_certificate_smoke.py --eligibility-only --executable "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

The browser check requires Playwright from `requirements-browser.txt`. Its
`--eligibility-only` mode guards the converter and fails if it is invoked.
Artifacts are saved to `dist/windows-eligibility-validation`; the test log is
`dist/phase17-tests.log`. Structured results are recorded in
`reports/phase17_windows_integration_validation.json`.

Use the routes actually registered in this application:

| Page | Local URL when the app runs on port 5555 |
| --- | --- |
| Student registration | `http://127.0.0.1:5555/register` |
| Student registration alias | `http://127.0.0.1:5555/student/register` |
| Student profile | `http://127.0.0.1:5555/profile` |
| Final SOC assessment | `http://127.0.0.1:5555/soc/final` |
| Assessment certificate eligibility | `http://127.0.0.1:5555/soc/final/certificate` |
| Original overall CTF certificate | `http://127.0.0.1:5555/soc/certificate` |

`/student/profile` is not a registered route; use `/profile`. The new assessment
certificate uses a separate URL to preserve the original overall and track
certificate rules. Configure `BLACK_FALCON_SECRET_KEY` and enable
`BLACK_FALCON_REGISTRATION_ENABLED=1` before launching an app for manual
enrollment. The automated browser check enables registration in its disposable
application and generates ephemeral credentials without printing them or
changing the development database.

## Phase 13: evidence reconciliation and final browser validation

Verified on 2026-11-05 with the project Python 3.12 virtual environment:

- Complete regression suite: **137 tests passed** (the previous 130 plus seven
  evidence reconciliation tests). The seven reconciliation tests also passed
  after the final epoch validation change.
- Project validator: all 15 cases passed; zero errors or warnings.
- Reconciliation: 30 Zeek records, nine candidate comparisons and 21 unanchored
  records. All seven evidence files retained identical SHA-256 hashes.
- Structural audit: 54 checks, zero errors, one chronology warning.
  `--strict-release` exits **2**; release readiness still requires review.
- Real headless Chrome through Playwright: **9/9 browser checklist items
  passed**, using disposable databases and local HTTP. No learner data was used.

Browser checklist completed:

- [x] Log in as an analyst and open the SOC dashboard.
- [x] Open all four guided practical labs and their investigation links.
- [x] Search and filter Wazuh, Suricata and Zeek events. Zeek upload records
  match the original 2025 date; the same 2026 date filter excludes them.
- [x] Open and save an individual alert triage decision.
- [x] Save a draft and submit an incident investigation report.
- [x] Complete the seven-question final assessment.
- [x] Verify the expected 74/100 score, seven feedback entries and assessment
  versus practice disclosure behavior.
- [x] Export CSV and verify the analyst and score.
- [x] Log out, log back in and verify saved report, triage and assessment data.

The run also verified analyst isolation, persistence after application restart,
the chronology advisory on all three BF-H-005 instruction pages and absence of
browser JavaScript errors. An assessment screenshot is saved at
`reports/BF-H-005_browser_assessment.png`.

Re-run the evidence and browser checks from the project root:

```powershell
.venv\Scripts\python.exe reconcile_bf_h_005.py
.venv\Scripts\python.exe tests\browser_soc_smoke.py --executable "C:\Program Files\Google\Chrome\Application\chrome.exe" --screenshot reports\BF-H-005_browser_assessment.png
```

Bare `py` selects Python 2.7 on this host. Use the Python 3 virtual environment.
See `reports/BF-H-005_timestamp_reconciliation.md`, the CSV and its source-hash
manifest for measured differences and limits. The advisory mitigates grading
ambiguity; it does not resolve the source timestamp conflict or authorize an
assumed correction. Ubuntu migration and OVA validation remain outstanding.

## Phase 11 verified application behavior

- Complete regression suite: 130 tests passed on Windows/Python 3.12.
- Project validator: all 15 configured cases passed with zero errors or warnings.
- Structural SOC integration audit: zero errors; the evidence chronology warning
  below remains. All original seven and five SOC blueprints are registered.
- Real headless Chrome through Playwright: login; all four guided-lab
  investigation links; Suricata and Wazuh searches; case and individual-alert
  triage; incident-report draft and submission; seven-question weighted final
  assessment; assessment/practice feedback; CSV download; cross-analyst
  isolation; application-restart persistence.
- Assessment defaults to private feedback. Regression tests cover private
  template context, legacy attempts, environment opt-in, no-store responses,
  CSRF checks, forged score fields, and analyst-scoped result/CSV access.
- Startup preserves existing users/password hashes and assessment rows.
  Tests and browser checks used disposable main/feature databases. No live
  learner database was used.

## Release blocker: evidence chronology

These are candidate cross-source alignments, not proof of a uniform clock
correction. Original BF-H-005 evidence remains unchanged.

| Record | Zeek time interpreted in +05:30 | Correlated Suricata time in +05:30 |
| --- | --- | --- |
| HTTP H02, suspected command injection | 2025-08-21 10:32:09.301 | 2026-08-21 10:32:09.301 |
| HTTP H05, periodic beacon | 2025-08-21 10:53:25.621 | 2026-08-21 10:43:25.621 |
| HTTP H06, outbound transfer | 2025-08-21 10:55:52.910 | 2026-08-21 10:45:52.910 |

Moving every timestamp forward one calendar year leaves some correlated
records ten minutes apart. One global offset is insufficient. Dataset owners
must establish canonical per-record timing or publish a separately reviewed,
provenanced normalized dataset before release. Do not silently rewrite raw
forensic evidence. Wazuh and Suricata remain authoritative for graded chronology.

The default audit reports this warning. --strict-release returns 2, and
release_ready is false. Passing code tests does not resolve this blocker.

## Still requiring the Ubuntu appliance

Real Wazuh deployment if required; systemd/service permissions; offline VM
networking; OVA export and fresh import; and learner workflows on that imported
appliance. These checks were not performed by Windows validation.

For secure exams, keep keys/grading outside the learner-controlled VM; local
assessment feedback restrictions do not prevent administrator access to source.
