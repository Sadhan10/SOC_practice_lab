# BF-H-005 evidence timestamp reconciliation

Prepared on 2026-11-05 (Asia/Calcutta). Original evidence remains unchanged.

The CSV contains all 30 records from the three BF-H-005 Zeek logs, including
the original epoch string, UTC and IST conversions, original line numbers,
network endpoints, application details and any selected Suricata comparison.
Nine rows have candidate comparison anchors; 21 are explicitly unanchored.
No independent timestamp is assigned to an unanchored record.

| Candidate Zeek record | Original Zeek time in IST | Suricata comparison in IST | Residual after hypothetical year alignment (seconds) |
| --- | --- | --- | ---: |
| conn R01, reconnaissance | 2025-08-21 10:04:11.003 | 2026-08-21 10:04:13.412 | -2.409 |
| conn R05, reconnaissance to port 445 | 2025-08-21 10:04:11.621 | 2026-08-21 10:04:13.412 | -1.791 |
| http H02, command injection | 2025-08-21 10:32:09.301 | 2026-08-21 10:32:09.301 | 0.000 |
| conn C01 / http H03, first suspected beacon | 2025-08-21 10:50:25.420 | 2026-08-21 10:43:25.621 | +419.799 |
| conn C03 / http H05, third suspected beacon | 2025-08-21 10:53:25.621 | 2026-08-21 10:43:25.621 | +600.000 |
| conn X01 / http H06, outbound upload | 2025-08-21 10:55:52.910 | 2026-08-21 10:45:52.910 | +600.000 |

All differences use **Zeek minus Suricata**. The CSV also records the complete
original difference in seconds, including the year discrepancy. The residual
column is a diagnostic calculation only: it replaces the year in memory for
comparison and never supplies a corrected event timestamp.

Suricata references are read from `evidence/suricata/BF-H-005_eve.json` at their
actual line numbers and copied verbatim into the CSV as supporting events.
The utility validates host pairs and destination ports before comparing them.
R01 is explicitly exceptional: it targets port 21 while the sweep alert targets
445. R05 targets 445, but a scan alert can summarize a sequence of packets.
Neither record is proven to be the packet that triggered the alert.

C01/H03 and C03/H05 are alternative candidate comparisons to the same periodic
beacon alert. Matching hosts, ports or fractional seconds cannot establish
which individual beacon produced that alert. A uniform year or clock shift is
therefore unsupported. H02 and the upload have stronger application context,
but these comparisons still do not establish replacement timestamps.

Wazuh additionally records recurring outbound communication at 2026 Aug 21
10:43:25 and a large outbound transfer at 10:45:52. The system process log
records the upload command at 2026-08-21 10:45:52. These two logs omit timezone
offsets. The authentication log omits both year and timezone. They corroborate
context and local clock readings; the utility does not infer missing date or
timezone components or claim an exact offset comparison to those records.

`BF-H-005_timestamp_reconciliation_sources.json` records byte counts and
SHA-256 hashes before and after reconciliation for all seven evidence files,
plus the generated CSV's SHA-256. All source hashes matched. These hashes
demonstrate preservation during this run; they do not authenticate the original
collection or establish when an event actually happened.

Run from the project root using Python 3:

```powershell
.venv\Scripts\python.exe reconcile_bf_h_005.py
```

The utility uses only the standard library and resolves evidence paths relative
to its own file. On this Windows host, bare `py` selects Python 2.7; use the
project virtual environment shown above. It writes only the derived CSV and
source manifest under `reports/`. It does not initialize application databases.

For graded timelines, use Wazuh and Suricata as stated in the learner advisory.
The advisory is displayed on the BF-H-005 investigation, incident report and
seven-question final assessment pages. The structural release warning remains
until dataset owners validate per-record timing against collection records or
publish a reviewed normalized derivative with provenance. No evidence
correction, migration or OVA export is performed by this reconciliation.
