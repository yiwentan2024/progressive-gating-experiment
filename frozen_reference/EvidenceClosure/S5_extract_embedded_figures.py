from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET
from zipfile import ZipFile
import sys

source = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)

REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
DRAWING_NS = "http://schemas.openxmlformats.org/drawingml/2006/main"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

with ZipFile(source) as archive:
    relationships = ET.fromstring(
        archive.read("word/_rels/document.xml.rels")
    )
    targets = {
        relationship.attrib["Id"]: relationship.attrib["Target"]
        for relationship in relationships.findall(f"{{{REL_NS}}}Relationship")
        if relationship.attrib.get("Type", "").endswith("/image")
    }

    document = ET.fromstring(archive.read("word/document.xml"))
    ordered_ids = []
    for blip in document.iter(f"{{{DRAWING_NS}}}blip"):
        relationship_id = blip.attrib.get(f"{{{OFFICE_REL_NS}}}embed")
        if relationship_id in targets and relationship_id not in ordered_ids:
            ordered_ids.append(relationship_id)

    if len(ordered_ids) != 4:
        raise ValueError(
            f"Expected four distinct figures referenced by the main document; "
            f"found {len(ordered_ids)}."
        )

    for number, relationship_id in enumerate(ordered_ids, 1):
        target = PurePosixPath(targets[relationship_id])
        member = str(PurePosixPath("word") / target)
        suffix = target.suffix.lower()
        (out / f"figure_{number}{suffix}").write_bytes(archive.read(member))
