"""Validate the approved SOC certificate template without PDF conversion."""

import unittest

from docx import Document

from certificate_generator import TEMPLATE, certificate_parts


EXPECTED_FIELDS = {
    "<<Name>>", "<<Course>>", "<<Score>>", "<<Certificate ID>>", "<<Date>>",
}


def get_document_text(container):
    """Include split runs, tables, nested tables, hyperlinks and text boxes.

    Document and header/footer part elements expose all descendant paragraphs;
    reading their text nodes preserves placeholders split across Word runs.
    """
    return "\n".join(
        "".join(node.text or "" for node in paragraph.xpath(".//w:t"))
        for paragraph in container.element.xpath(".//w:p")
    )


class CertificateTemplateTests(unittest.TestCase):
    def test_template_exists(self):
        self.assertTrue(TEMPLATE.is_file(), f"Missing certificate template: {TEMPLATE}")

    def test_required_placeholders(self):
        document = Document(TEMPLATE)
        text = "\n".join(get_document_text(part) for part in certificate_parts(document))
        missing = sorted(field for field in EXPECTED_FIELDS if field not in text)
        self.assertEqual(missing, [], f"Missing certificate placeholders: {missing}")

    def test_template_uses_landscape_sections(self):
        for index, section in enumerate(Document(TEMPLATE).sections, 1):
            self.assertGreater(section.page_width, section.page_height, f"Section {index} must be landscape")

    def test_template_contains_embedded_artwork(self):
        document = Document(TEMPLATE)
        image_parts = {
            relation.target_part.partname
            for part in certificate_parts(document)
            for relation in part.rels.values()
            if not relation.is_external and relation.reltype.rsplit("/", 1)[-1] == "image"
        }
        self.assertGreaterEqual(len(image_parts), 2, "The template must retain its embedded logo and signature artwork")


if __name__ == "__main__":
    unittest.main()
