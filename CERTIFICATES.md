# Phase 14: personalized final SOC certificates

Open `/soc/final/certificate` after passing the independent Final SOC Assessment
with at least 70/100. The page reads `final_soc_attempts`, selects the highest
qualifying saved score, reads the registered student profile's full name, and previews the name, course and
verified score. Confirming that preview assigns a unique ID and UTC issue date
and saves the PDF, its SHA-256 digest and source attempt ID in `soc_certificates`
in the main SQLite database. Repeat downloads return the exact saved bytes,
including after later attempts, template changes or application restarts.

Phase 15 adds enrollment-gated accounts and immutable profile names. Students
cannot enter another name on the certificate page. Legacy accounts without a
profile can download existing PDFs but cannot issue new ones. See
[STUDENT_ACCOUNTS.md](STUDENT_ACCOUNTS.md) for registration and identity setup.

The app factory initializes the new table without changing existing records.
CSRF protection applies to preview and issuance. All routes require a signed-in
username, and certificate reads and downloads are scoped to that username.
The server rechecks the previewed attempt before and after conversion. A unique
database constraint allows only one certificate per account and course.

The existing `/soc/certificate` overall certificate and
`/soc/certificate/<level_name>` track certificates retain their original rules.
The new workflow uses a separate URL to avoid taking over the existing overall
certificate. This project stores final assessment attempts in
`final_soc_attempts`, rather than the `final_soc_results` name in the outline.

## Local setup

Use the project's Python 3 virtual environment on Windows; bare `py` selects
Python 2.7 on this host:

```powershell
.venv\Scripts\python.exe -m pip install "python-docx>=1.2,<2" "pypdf>=6,<7"
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe validate_project.py
.venv\Scripts\python.exe audit_soc_integration.py
```

Install [LibreOffice](https://www.libreoffice.org/download/) for local PDF
conversion. The generator searches PATH and standard Windows locations.
Alternatively set `BLACK_FALCON_SOFFICE` to the full `soffice.com` path before
starting the app. Ubuntu packages and service timeouts are documented in
[deploy/README.md](deploy/README.md). Each conversion uses an isolated temporary
profile and has a 60-second limit, following the
[LibreOffice command-line interface](https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html).
Downloading or converting a certificate sends no student data to a service.

This workspace also has an extracted LibreOffice runtime for validation in the
ignored `dist/certificate-tools/libreoffice` directory. To use that runtime
when starting the app from this project root:

```powershell
$env:BLACK_FALCON_SOFFICE = (Resolve-Path "dist\certificate-tools\libreoffice\program\soffice.com").Path
# Set BLACK_FALCON_SECRET_KEY to your existing application secret as usual.
.venv\Scripts\python.exe app.py
```

The extracted runtime is a local validation tool, excluded from student builds.
Install LibreOffice normally on deployment hosts instead of shipping that
Windows runtime inside the Ubuntu OVA.

The template is `certificate_templates/certificate_of_completion.docx`.
Generation retains its formatted runs, images, headers, footers and tables.
A missing converter, incomplete template, failed conversion, unreadable PDF,
portrait page or multiple pages prevents issuance and leaves the preview
available for retry. Downloading an already issued PDF needs no converter.
Issued PDFs and names are part of the main database backup.

## Render and release checks

Render the template with the deployment's LibreOffice and fonts. Check that the
full name, course, score, ID, date, logo, signature and director designation are
visible on exactly one landscape page. Page-count validation cannot detect
clipped text or overlapping artwork, so visual review remains necessary.
Test long names and confirm rendering again after changes to fonts or template.

Before distribution, replace shared training-account provisioning with secure
instructor provisioning and confirm authorization to issue under the template's
branding and director signature. Student registration is available in Phase 15.
The registered full name is self-declared and does not verify legal identity.

Automated checks use disposable databases and mocked conversion, including
passing boundaries, name validation, preview confirmation, account isolation,
repeat issuance, changed eligibility, saved PDF persistence and conversion
failure. Generator checks cover split runs, preserved artwork and package
parts, conversion arguments, timeout/error handling and PDF page validation.
These checks do not replace Ubuntu/OVA validation.

## Verified on November 7, 2026

All 159 regression tests passed on Python 3.12, including 22 certificate tests.
Project validation passed for all 15 cases with no errors or warnings. The
structural integration audit passed with 65 checks; its existing BF-H-005 Zeek
timestamp warning still requires release review.

The real Chrome/LibreOffice browser check passed: complete the seven-question
assessment, enter and preview a full name, issue a PDF, log out and back in,
download identical bytes, then confirm that another account cannot download
the certificate. The generated PDF has exactly one landscape page. Visual
inspection confirmed the full name, course, score, ID, date, logo, signature,
director name and designation. The certificate ID line was reduced to 10 pt
with a fixed 29.3 pt line height to avoid the signature while retaining the
original vertical placement of the director block. The original Word file is
backed up under `dist/certificate-validation/original_certificate_template.docx`.

To repeat the browser check with installed Chrome and the extracted runtime:

```powershell
.venv\Scripts\python.exe tests/browser_certificate_smoke.py `
  --executable "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --soffice $env:BLACK_FALCON_SOFFICE
```

The browser script now runs the Phase 15 registration and profile-name flow
for two individual students, rather than the earlier shared-account name-entry
flow. Its default artifact directory is `dist/student-identity-validation`.
It requires the optional Playwright dependency from `requirements-browser.txt`.
The check uses disposable databases and test accounts. PDF and screenshot
artifacts are saved under the selected output directory. Standard regression
tests mock conversion and need neither Chrome nor LibreOffice.

## Phase 16: standalone template verification

`preview_soc_certificate.py` renders the requested sample for Akshata P Pawashe
with score `86/100`, certificate ID `BF-SOC-PREVIEW-001` and issue date
`07 November 2026`. It writes `reports/certificate_preview.pdf`, without
starting Flask, opening a database or creating a certificate issuance record.
It uses the existing generator's `name` and `date` arguments for the student
name and issue date. The one-page landscape validation remains enforced.

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -p "test_certificate_template.py" -v
# Use the extracted runtime on this workspace, or an installed LibreOffice.
$env:BLACK_FALCON_SOFFICE = (Resolve-Path "dist\certificate-tools\libreoffice\program\soffice.com").Path
.venv\Scripts\python.exe preview_soc_certificate.py
Start-Process ".\reports\certificate_preview.pdf"
```

An explicit executable can instead be supplied with `--soffice PATH`.
The four template tests check existence, all five placeholders across Word
runs and document parts, landscape sections, and embedded artwork. The
existing generator tests also verify that personalization preserves artwork
and other package parts and that invalid/multiple-page PDFs are rejected.

On November 7, 2026, actual LibreOffice conversion produced a 121,118-byte PDF
with one 792 by 612 point landscape page. Text extraction verified all five
sample fields; visual inspection confirmed the ReinFosec logo, signature,
director name and designation were visible. No template adjustment was needed.
Its SHA-256 digest is
`315442718fcb4e25607cf346d5a7a8da40f27e4c163bd0166d4b1fba458e7338`.
The rendered inspection image is `dist/phase16-certificate-preview.png`.

The complete regression suite passed all 182 tests. Project validation passed
all 15 cases, and the structural audit passed 74 checks with the existing
BF-H-005 timestamp warning. Results are recorded in
`reports/phase16_certificate_validation.json`. The account-rotation utility was
created and syntax-checked without executing it or changing current passwords.
