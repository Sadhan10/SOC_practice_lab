"""Render a sample certificate for layout review without issuing a certificate."""

import argparse
from pathlib import Path

from certificate_generator import CertificateGenerationError, generate_certificate_pdf


OUTPUT = Path(__file__).resolve().parent / "reports" / "certificate_preview.pdf"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--soffice", help="Optional path to the local LibreOffice executable.")
    args = parser.parse_args()
    try:
        # Use the existing generator API: name/date correspond to the
        # student_name/issue_date fields in the integration outline.
        pdf_bytes = generate_certificate_pdf(
            name="Akshata P Pawashe",
            course="Operation Black Falcon - SOC Investigation",
            score="86/100",
            certificate_id="BF-SOC-PREVIEW-001",
            date="07 November 2026",
            soffice_path=args.soffice,
        )
    except CertificateGenerationError as error:
        raise SystemExit(f"Certificate preview failed: {error}") from error
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(pdf_bytes)
    print("Certificate rendering successful.")
    print(f"PDF saved to: {OUTPUT}")
    print(f"PDF size: {len(pdf_bytes):,} bytes")
    print("Certificate pages: 1 (landscape)")
    print("Sample preview only. No certificate issuance record was created.")


if __name__ == "__main__":
    main()
