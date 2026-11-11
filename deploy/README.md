# Ubuntu deployment

Deploy the application to `/var/www/black_falcon` and keep the protected
solution store outside the web project at
`/var/lib/black-falcon/solutions.json`.

## Service account and protected data

```bash
sudo useradd --system \
  --home /var/lib/black-falcon \
  --shell /usr/sbin/nologin \
  blackfalcon

sudo mkdir -p /var/lib/black-falcon
sudo cp /var/www/black_falcon/private/solutions.json \
  /var/lib/black-falcon/solutions.json
sudo chown blackfalcon:blackfalcon \
  /var/lib/black-falcon/solutions.json
sudo chmod 600 /var/lib/black-falcon/solutions.json
sudo rm -rf /var/www/black_falcon/private
```

## Application permissions

```bash
sudo chown -R blackfalcon:blackfalcon /var/www/black_falcon
sudo find /var/www/black_falcon -type d -exec chmod 755 {} \;
sudo find /var/www/black_falcon -type f -exec chmod 644 {} \;
sudo chmod 750 /var/www/black_falcon/database
sudo chmod 660 /var/www/black_falcon/database/black_falcon.db
sudo chmod 750 /var/www/black_falcon/instance
sudo chmod 660 /var/www/black_falcon/instance/soc_features.db
sudo mkdir -p /var/www/black_falcon/logs
sudo chown blackfalcon:blackfalcon /var/www/black_falcon/logs
```

## Python environment

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libreoffice-writer fonts-liberation
cd /var/www/black_falcon
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Final SOC certificate conversion uses local LibreOffice Writer. Its headless
process needs a writable temporary directory; each conversion uses a separate
profile there. Keep the certificate template at
`certificate_templates/certificate_of_completion.docx` and install any fonts
required by its design before checking the rendered PDF. The generator rejects
anything other than one landscape page. See the official
[LibreOffice command-line documentation](https://help.libreoffice.org/latest/en-US/text/shared/guide/start_parameters.html).

Requests that issue a PDF can take up to 60 seconds. If using Gunicorn, allow
extra time for conversion and database work by setting its worker timeout to
90 seconds. Backups of `database/black_falcon.db` now include issued PDFs and
the associated student names; retain database access restrictions. Certificate
downloads read the saved bytes without requiring LibreOffice.

Generate a session secret with `openssl rand -hex 32`. Copy
`deploy/black-falcon.env.example` to `/etc/black-falcon.env`, replace the secret
placeholder, then protect it:

```bash
sudo chown root:blackfalcon /etc/black-falcon.env
sudo chmod 640 /etc/black-falcon.env
```

To enable individual student registration during local training, set
`BLACK_FALCON_REGISTRATION_ENABLED=1` in that protected environment file before
restarting the service. Unset or `0` disables self-registration with HTTP 503.
Registration no longer requires an enrollment code; USN is optional. Anyone
who can reach an enabled registration page may create an account. Restrict the
service to the local training network and disable registration after enrollment.
The development server defaults to loopback; the systemd service retains its
training-network bind. `BLACK_FALCON_HOST` only changes the development server.
The `student_profiles` (including the optional `usn` migration) and
`auth_rate_limits` tables are initialized by the application factory. Existing
passwords and learner records are preserved. New assessment certificates require
a student profile; old issued PDFs remain downloadable. See
[STUDENT_ACCOUNTS.md](../STUDENT_ACCOUNTS.md) for identity and attempt-limit rules
and remaining shared-account provisioning work.

Validate the installed application after the protected store and environment
file are in place:

```bash
set -a
source /etc/black-falcon.env
set +a
python3 validate_project.py
```

Remove generated Python caches before sealing the OVA:

```bash
find /var/www/black_falcon -type d -name "__pycache__" \
  -prune -exec rm -rf {} +
find /var/www/black_falcon -type f -name "*.pyc" -delete
```

## systemd

```bash
sudo cp deploy/black-falcon.service \
  /etc/systemd/system/black-falcon.service
sudo systemctl daemon-reload
sudo systemctl enable --now black-falcon
sudo systemctl status black-falcon
```

Follow service logs with:

```bash
journalctl -u black-falcon -f
```

## SOC Operations upgrade and release validation

The app factory creates `operations_triage` and `operations_assessments` in
`database/black_falcon.db`. Existing users, progress, validated findings and flag
submissions remain in their original tables. No manual schema command is needed.
Triage and reports are isolated by analyst username and case ID. Back up the
SQLite database before upgrading an existing installation; stop the service
while copying it, or use SQLite's online backup command.

Incident reports have eight narrative sections and factual checks drawn from the
existing case questions. Completion measures filled narrative sections; evidence
accuracy uses the accepted answer hashes in the protected solution store. No
plaintext answer key is added to the application. Narrative correctness and
response quality still need instructor review. A missing or incomplete rubric
makes accuracy unavailable instead of awarding a misleading score. Restoring the
rubric and saving a report again recalculates its accuracy.

The Assessment Center determines a pass separately: the report must be submitted
with all eight sections containing at least 20 characters after trimming
surrounding whitespace, and the existing challenge progress must show
both validated findings and an accepted flag. Saved report scores cannot replace
those verified results. The dashboard reads live progress without changing flag
scores, certificates or submission records. Free-text report correctness still
requires instructor review.

Drafts may contain shorter sections, but those sections receive no completion
credit. Submission validation, saved completion scores and the assessment
dashboard use the same minimum-length calculation. Older short reports are
recalculated on the dashboard and cannot pass using a previously saved score.

For a release-validation checkout containing `tests`, run the complete suite as
the service account after loading `/etc/black-falcon.env`. The tests isolate their
SQLite databases in temporary directories and include project validation for all
15 challenges. Set the protected solution-store path for the service account's
test process; do not copy the store into the public project or student bundle.

```bash
cd /var/www/black_falcon
sudo -u blackfalcon env \
  BLACK_FALCON_SOLUTION_STORE=/var/lib/black-falcon/solutions.json \
  /var/www/black_falcon/venv/bin/python -m unittest discover -s tests -v
```

After validation, restart the service, confirm its status and log in through
the VM's web interface. Check SIEM date/severity filters, save a triage decision,
save a partial report draft, then submit a report with factual answers. Restart
the service and confirm those records persist for that analyst and remain private
when another analyst signs in. Confirm original challenge submissions still work.
These VM checks are required even when the Windows test suite passes; static
deployment checks do not prove that Ubuntu networking or systemd is operational.

## OVA export after Ubuntu verification

Export a clean, powered-off training VM after the Ubuntu checks pass. For a fresh
student appliance, remove test analyst activity from a disposable validation
clone or start it with new runtime databases; preserve existing work on an
upgraded live installation. The protected hashed solution store must remain
inside the appliance at `/var/lib/black-falcon/solutions.json` for grading to work,
with the service-account permissions above. Exclude instructor credentials,
source-control metadata and validation artifacts from the release image.

On the VirtualBox host, substitute the actual Ubuntu VM name and output path:

```powershell
& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' export 'YOUR_UBUNTU_VM' --output 'C:\release\BlackFalcon.ova' --ovf20
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\release\BlackFalcon.ova'
```

Import the exported OVA as a separate VM and repeat the login, investigation,
triage/report persistence and cross-analyst privacy checks before distribution.
Keep the OVA checksum alongside the release. A completed export alone does not
verify that an imported appliance works.


## Assessment release configuration

Keep BLACK_FALCON_SHOW_ASSESSMENT_ANSWERS=0 in the OVA environment. The default
Assessment Mode omits expected answers and explanations. Set it to 1 only for
deliberate practice, then restart the service. The legacy
FINAL_SOC_SHOW_EXPECTED_ANSWERS setting does not enable disclosure.

Run audit_soc_integration.py for a disposable structural audit; use
--strict-release to fail when release warnings remain. --database targets only
an explicit development copy and can initialize missing tables. Do not use an
important student database. See WINDOWS_VALIDATION.md for the Windows test
record and the unresolved BF-H-005 timestamp discrepancies.

Local assessment mode does not protect answer keys from an administrator of
the offline VM. Secure examinations need externally hosted keys and grading.
Ubuntu service, Wazuh integration, offline networking, fresh OVA import, and
learner persistence still require validation on the actual Ubuntu appliance.
