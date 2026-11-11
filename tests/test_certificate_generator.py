"""Word certificate personalization and template preservation checks."""

import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile
from unittest.mock import patch

from docx import Document
from docx.oxml import OxmlElement
from lxml import etree
from pypdf import PdfWriter

from certificate_generator import (
    TEMPLATE,
    CertificateGenerationError,
    generate_certificate,
    generate_certificate_pdf,
    replace_in_paragraph,
    validate_certificate_pdf,
)


def xml_contents(element):
    """Compare XML content without declaration and attribute order changes."""
    return (
        element.tag,
        sorted(element.attrib.items()),
        element.text,
        [xml_contents(child) for child in element],
    )


class CertificateGeneratorTests(unittest.TestCase):
    def test_split_runs_keep_formatting_and_embedded_drawing(self):
        document = Document()
        paragraph = document.add_paragraph()
        first = paragraph.add_run("Presented to <<Na")
        first.bold = True
        drawing = OxmlElement("w:drawing")
        first._r.append(drawing)
        last = paragraph.add_run("me>> with distinction")
        last.italic = True

        replace_in_paragraph(paragraph, {"<<Name>>": "Ada Lovelace"})

        self.assertEqual(paragraph.text, "Presented to Ada Lovelace with distinction")
        self.assertTrue(first.bold)
        self.assertTrue(last.italic)
        self.assertIs(drawing.getparent(), first._r)
        self.assertIn("Ada Lovelace", first.text)
        self.assertEqual(last.text, " with distinction")

    def test_multiple_matches_insert_values_literally(self):
        paragraph = Document().add_paragraph("<<Name>> / <<Name>> / <<Date>>")
        replace_in_paragraph(paragraph, {
            "<<Name>>": "Ada <<Date>>",
            "<<Date>>": "Today",
        })
        self.assertEqual(paragraph.text, "Ada <<Date>> / Ada <<Date>> / Today")

    def test_generation_handles_tables_and_existing_headers_and_footers(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "template.docx"
            document = Document()
            cell = document.add_table(rows=1, cols=1).cell(0, 0)
            cell.add_table(rows=1, cols=1).cell(0, 0).text = "<<Course>>"
            document.sections[0].header.paragraphs[0].text = "<<Name>>"
            document.sections[0].footer.paragraphs[0].text = "<<Certificate ID>>"
            document.save(template)
            original = template.read_bytes()

            output = generate_certificate(
                "Ada", "SOC", "98%", "SOC-001", "2026-11-07",
                Path(directory) / "output" / "certificate.docx",
                template_path=template,
            )
            result = Document(output)
            self.assertEqual(result.tables[0].cell(0, 0).tables[0].cell(0, 0).text, "SOC")
            self.assertEqual(result.sections[0].header.paragraphs[0].text, "Ada")
            self.assertEqual(result.sections[0].footer.paragraphs[0].text, "SOC-001")
            self.assertEqual(template.read_bytes(), original)

    def test_project_template_preserves_other_package_parts(self):
        with tempfile.TemporaryDirectory() as directory:
            original = TEMPLATE.read_bytes()
            output = generate_certificate(
                "Ada Lovelace", "SOC Analyst", "98%", "SOC-001", "2026-11-07",
                Path(directory) / "certificate.docx",
            )
            text = "\n".join(p.text for p in Document(output).paragraphs)
            for value in ("Ada Lovelace", "SOC Analyst", "98%", "SOC-001", "2026-11-07"):
                self.assertIn(value, text)
            self.assertNotIn("<<", text)
            self.assertEqual(TEMPLATE.read_bytes(), original)
            with ZipFile(TEMPLATE) as source, ZipFile(output) as result:
                self.assertEqual(set(source.namelist()), set(result.namelist()))
                for name in source.namelist():
                    if name != "word/document.xml":
                        before, after = source.read(name), result.read(name)
                        if name.endswith((".xml", ".rels")):
                            # Word parts can be serialized with different XML
                            # declarations or attribute ordering when saved.
                            source_xml = etree.fromstring(before)
                            result_xml = etree.fromstring(after)
                            if name == "[Content_Types].xml" or name.endswith(".rels"):
                                # Package manifests are unordered collections.
                                for root in (source_xml, result_xml):
                                    root[:] = sorted(root, key=lambda child: (
                                        child.tag, sorted(child.attrib.items())
                                    ))
                            before = xml_contents(source_xml)
                            after = xml_contents(result_xml)
                        self.assertEqual(before, after, name)

    def test_output_cannot_overwrite_template(self):
        with self.assertRaises(ValueError):
            generate_certificate("Ada", "SOC", "98%", "SOC-001", "Today", TEMPLATE)

    def pdf_bytes(self, *, pages=1, width=792, height=612, encrypted=False):
        writer = PdfWriter()
        for _ in range(pages):
            writer.add_blank_page(width=width, height=height)
        if encrypted:
            writer.encrypt("password")
        output = io.BytesIO()
        writer.write(output)
        return output.getvalue()

    def test_pdf_validation_rejects_invalid_page_counts_orientation_and_encryption(self):
        pdf = self.pdf_bytes()
        self.assertEqual(validate_certificate_pdf(pdf), pdf)
        for invalid in (b"invalid", self.pdf_bytes(pages=0), self.pdf_bytes(pages=2),
                        self.pdf_bytes(width=612, height=792), self.pdf_bytes(encrypted=True)):
            with self.subTest(pdf_length=len(invalid)), self.assertRaises(CertificateGenerationError):
                validate_certificate_pdf(invalid)

    def test_conversion_uses_isolated_profile_and_removes_temporary_files(self):
        pdf = self.pdf_bytes()
        sources = []
        def convert(command, **kwargs):
            self.assertIn("--headless", command)
            self.assertIn("pdf:writer_pdf_Export", command)
            self.assertEqual(kwargs["timeout"], 60)
            self.assertTrue(command[1].startswith("-env:UserInstallation=file:///"))
            source = Path(command[-1])
            sources.append(source)
            self.assertTrue(source.is_file())
            output = Path(command[command.index("--outdir") + 1])
            (output / "certificate.pdf").write_bytes(pdf)
            return subprocess.CompletedProcess(command, 0)
        original = TEMPLATE.read_bytes()
        with patch("certificate_generator.find_soffice", return_value="soffice"), \
                patch("certificate_generator.subprocess.run", side_effect=convert):
            result = generate_certificate_pdf("Ada", "SOC", "74/100", "OBF-001", "Today")
        self.assertEqual(result, pdf)
        self.assertFalse(sources[0].parent.exists())
        self.assertEqual(TEMPLATE.read_bytes(), original)

    def test_missing_template_fields_and_conversion_failure_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            template = Path(directory) / "missing-fields.docx"
            Document().save(template)
            with patch("certificate_generator.find_soffice", return_value="soffice"), \
                    patch("certificate_generator.subprocess.run") as convert:
                with self.assertRaisesRegex(CertificateGenerationError, "missing required placeholders"):
                    generate_certificate_pdf("Ada", "SOC", "74/100", "ID", "Today", template_path=template)
                convert.assert_not_called()
        for effect in (subprocess.TimeoutExpired("soffice", 60),
                       subprocess.CompletedProcess(["soffice"], 1),
                       subprocess.CompletedProcess(["soffice"], 0)):
            with self.subTest(effect=effect), \
                    patch("certificate_generator.find_soffice", return_value="soffice"), \
                    patch("certificate_generator.subprocess.run") as convert:
                if isinstance(effect, Exception):
                    convert.side_effect = effect
                else:
                    convert.return_value = effect
                with self.assertRaises(CertificateGenerationError):
                    generate_certificate_pdf("Ada", "SOC", "74/100", "ID", "Today")


if __name__ == "__main__":
    unittest.main()
