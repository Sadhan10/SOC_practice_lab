"""Personalize the Word template and produce a single landscape PDF locally."""

import io
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn
from docx.text.paragraph import Paragraph
from pypdf import PdfReader


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE = (
    BASE_DIR
    / "certificate_templates"
    / "certificate_of_completion.docx"
)
PLACEHOLDERS = ("<<Name>>", "<<Course>>", "<<Score>>", "<<Certificate ID>>", "<<Date>>")


class CertificateGenerationError(RuntimeError):
    """Conversion or template validation failed; no certificate may be issued."""


def certificate_parts(document):
    """Yield the body and existing header/footer parts without creating parts."""
    yield document.part
    for relationship in document.part.rels.values():
        if (not relationship.is_external
                and relationship.reltype.rsplit("/", 1)[-1] in {"header", "footer"}):
            yield relationship.target_part


def replace_in_paragraph(paragraph, replacements):
    """Replace placeholders split across runs, preserving surrounding XML.

    Replacement text inherits the formatting at the placeholder's first
    character. Other runs, drawings, paragraph properties and styles survive.
    Values are inserted literally and are never treated as placeholders.
    """
    if not replacements:
        return
    if any(not isinstance(key, str) or not key for key in replacements):
        raise ValueError("Placeholders must be non-empty strings.")

    # Work on text nodes so updating a run cannot discard embedded artwork.
    # Tabs and line breaks form boundaries in the searchable text.
    positions = []
    parts = []
    offset = 0
    for node in paragraph._p.xpath(".//w:t | .//w:tab | .//w:br | .//w:cr"):
        if next(node.iterancestors(qn("w:p"))) is not paragraph._p:
            continue
        if node.tag == qn("w:t"):
            text = node.text or ""
        elif node.tag == qn("w:tab"):
            text = "\t"
        else:
            text = "\n"
        positions.append((node, offset, offset + len(text)))
        parts.append(text)
        offset += len(text)

    original = "".join(parts)
    pattern = re.compile("|".join(
        re.escape(key) for key in sorted(replacements, key=len, reverse=True)
    ))
    # Editing from the end keeps original character offsets valid, including
    # when several placeholders share one run or a value contains a placeholder.
    for match in reversed(list(pattern.finditer(original))):
        affected = [
            (node, start, end)
            for node, start, end in positions
            if start < match.end() and end > match.start()
        ]
        first, start, _ = affected[0]
        last, last_start, _ = affected[-1]
        prefix = (first.text or "")[:match.start() - start]
        suffix = (last.text or "")[match.end() - last_start:]

        # A temporary run lets python-docx encode tabs, newlines and spaces
        # correctly. Insert its text children beside the first original node.
        replacement_run = paragraph.add_run()
        replacement_run.text = str(replacements[match.group()])
        if first is last:
            replacement_run.text += suffix
        parent = first.getparent()
        insertion_index = parent.index(first) + 1
        for child in list(replacement_run._r):
            parent.insert(insertion_index, child)
            insertion_index += 1
        paragraph._p.remove(replacement_run._r)

        first.text = prefix
        first.set(qn("xml:space"), "preserve")

        if first is not last:
            last.text = suffix
            last.set(qn("xml:space"), "preserve")
        for node, _, _ in affected:
            if node is first or (node is last and first is not last):
                continue
            node.getparent().remove(node)


def generate_certificate(
    name, course, score, certificate_id, date, output_path, *, template_path=TEMPLATE
):
    """Save a personalized .docx certificate and return its Path.

    ``score`` and ``date`` are displayed exactly as supplied by the caller.
    The template is read afresh for each certificate and is never overwritten.
    """
    template_path = Path(template_path)
    output_path = Path(output_path)
    if output_path.suffix.lower() != ".docx":
        raise ValueError("The certificate output must have a .docx extension.")
    if output_path.resolve() == template_path.resolve():
        raise ValueError("The output path must differ from the template path.")

    replacements = {
        "<<Name>>": name,
        "<<Course>>": course,
        "<<Score>>": score,
        "<<Certificate ID>>": certificate_id,
        "<<Date>>": date,
    }
    document = Document(template_path)
    # Descendant paragraphs include tables, nested tables and text boxes.
    # Visit existing header/footer parts directly to retain section linkage.
    for part in certificate_parts(document):
        for element in part.element.xpath(".//w:p"):
            replace_in_paragraph(Paragraph(element, part), replacements)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    document.save(output_path)
    return output_path


def find_soffice(configured_path=None):
    """Find LibreOffice on Windows or Linux, respecting an explicit override."""
    configured_path = configured_path or os.environ.get("BLACK_FALCON_SOFFICE")
    if configured_path:
        resolved = shutil.which(str(configured_path))
        if resolved:
            return resolved
        raise CertificateGenerationError("The configured LibreOffice executable was not found.")
    for executable in ("soffice", "libreoffice"):
        resolved = shutil.which(executable)
        if resolved:
            return resolved
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        directory = os.environ.get(variable)
        if directory:
            for executable in ("soffice.com", "soffice.exe"):
                candidate = Path(directory) / "LibreOffice" / "program" / executable
                if candidate.is_file():
                    return str(candidate)
    raise CertificateGenerationError(
        "LibreOffice is required. Install Writer or configure BLACK_FALCON_SOFFICE."
    )


def validate_certificate_pdf(pdf_bytes):
    """Reject malformed, encrypted, multi-page or portrait certificates."""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)
        if reader.is_encrypted or len(reader.pages) != 1:
            raise CertificateGenerationError("The certificate must have exactly one unencrypted page.")
        page = reader.pages[0]
        width, height = float(page.mediabox.width), float(page.mediabox.height)
        if page.rotation % 180:
            width, height = height, width
        if width <= height or height <= 0:
            raise CertificateGenerationError("The certificate must use a landscape page.")
    except CertificateGenerationError:
        raise
    except Exception as error:
        raise CertificateGenerationError("The converted certificate is not a readable PDF.") from error
    return pdf_bytes


def generate_certificate_pdf(
    name, course, score, certificate_id, date, *, template_path=TEMPLATE,
    soffice_path=None, timeout=60,
):
    """Return validated PDF bytes using an isolated, temporary LibreOffice profile.

    No files are retained and the original template is never modified. A
    conversion or layout failure raises CertificateGenerationError.
    """
    executable = find_soffice(soffice_path)
    try:
        template = Document(template_path)
        template_text = "\n".join(
            "".join(node.text or "" for node in element.xpath(".//w:t"))
            for part in certificate_parts(template)
            for element in part.element.xpath(".//w:p")
        )
        missing = [placeholder for placeholder in PLACEHOLDERS if placeholder not in template_text]
        if missing:
            raise CertificateGenerationError("The certificate template is missing required placeholders.")
        with tempfile.TemporaryDirectory(prefix="black-falcon-certificate-") as directory:
            root = Path(directory)
            source = generate_certificate(
                name, course, score, certificate_id, date, root / "certificate.docx",
                template_path=template_path,
            )
            output = root / "pdf"
            output.mkdir()
            result = subprocess.run(
                [executable, "-env:UserInstallation=" + (root / "profile").as_uri(),
                 "--headless", "--nologo", "--nodefault", "--nofirststartwizard",
                 "--convert-to", "pdf:writer_pdf_Export", "--outdir", str(output), str(source)],
                capture_output=True, timeout=timeout, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            pdf = output / "certificate.pdf"
            if result.returncode != 0 or not pdf.is_file():
                raise CertificateGenerationError("LibreOffice did not produce a certificate PDF.")
            return validate_certificate_pdf(pdf.read_bytes())
    except CertificateGenerationError:
        raise
    except subprocess.TimeoutExpired as error:
        raise CertificateGenerationError("Certificate PDF conversion timed out.") from error
    except Exception as error:
        raise CertificateGenerationError("Certificate PDF generation failed.") from error
