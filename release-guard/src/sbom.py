"""CycloneDX 1.5 SBOM из pinned requirements. Без временных меток и случайных UUID - SBOM тоже воспроизводим."""
import json
import re
import uuid

from repro import sha256


class SbomError(Exception): pass


_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([A-Za-z0-9._+!-]+)\s*(?:#.*)?$")


def parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PIN.match(line)
        if not m:
            raise SbomError(f"строка {n}: зависимость не зафиксирована через '==': {line!r}")
        out.append((m.group(1).lower().replace("_", "-"), m.group(3)))
    return sorted(set(out))


def build_sbom(name: str, version: str, artifact_sha256: str, requirements: str) -> bytes:
    comps = [{"type": "library", "bom-ref": f"pkg:pypi/{n}@{v}", "name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"}
             for n, v in parse_requirements(requirements)]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "serialNumber": "urn:uuid:" + str(uuid.UUID(artifact_sha256[:32])), "version": 1,
           "metadata": {"component": {"type": "application", "name": name, "version": version,
                                       "hashes": [{"alg": "SHA-256", "content": artifact_sha256}]}},
           "components": comps}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def components(sbom: bytes) -> set[tuple[str, str]]:
    try:
        doc = json.loads(sbom)
        if doc["bomFormat"] != "CycloneDX":
            raise SbomError("не CycloneDX")
        return {(c["name"], c["version"]) for c in doc["components"]}
    except (KeyError, TypeError, json.JSONDecodeError) as e:
        raise SbomError(f"битый SBOM: {e}")
