"""Выпуск и проверка релиза: артефакт + SBOM + in-toto/SLSA provenance в DSSE + запись в журнал прозрачности."""
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field

_here = os.path.dirname(os.path.abspath(__file__))
for sub in ("../../transparency-log/src",):
    sys.path.insert(0, os.path.normpath(os.path.join(_here, sub)))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import merkle
from tlog import verify_sth_signature
from dsse import DsseError, sign_envelope, verify_envelope
from repro import deterministic_targz, sha256
from wheel import build_wheel, wheel_filename
from sbom import SbomError, build_sbom, components, parse_requirements

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


class ReleaseRejected(Exception): pass


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def log_entry(artifact_sha: str, envelope: dict) -> bytes:
    return b"release-v1\n" + _canon({"artifact_sha256": artifact_sha, "envelope_sha256": sha256(_canon(envelope))})


def make_statement(name: str, artifact_sha: str, sbom_sha: str, builder_id: str, source_sha: str) -> dict:
    return {"_type": STATEMENT_TYPE, "subject": [{"name": name, "digest": {"sha256": artifact_sha}}],
            "predicateType": PROVENANCE_TYPE,
            "predicate": {"buildDefinition": {"buildType": "https://example.invalid/reproducible-targz/v1",
                                              "externalParameters": {"source_tree_sha256": source_sha},
                                              "resolvedDependencies": [{"name": "sbom", "digest": {"sha256": sbom_sha}}]},
                          "runDetails": {"builder": {"id": builder_id}}}}


@dataclass
class Bundle:
    envelope: dict
    sbom: bytes
    log: dict      # {index, sth, proof:[hex]}


def components_requires(sbom: bytes) -> list[str]:
    return [f"{n}=={v}" for n, v in sorted(components(sbom))]


def tree_digest(src_dir: str) -> str:
    return sha256(deterministic_targz(src_dir))


def build_release(src_dir: str, name: str, version: str, requirements: str, signers, tlog,
                  builder_id: str = "https://example.invalid/builder/1", kind: str = "tar.gz"):
    if kind == "wheel":
        artifact, fname = build_wheel(src_dir, name, version, [f"{n}=={v}" for n, v in parse_requirements(requirements)]), wheel_filename(name, version)
    else:
        artifact, fname = deterministic_targz(src_dir, prefix=f"{name}-{version}/"), f"{name}-{version}.tar.gz"
    a_sha = sha256(artifact)
    sbom = build_sbom(name, version, a_sha, requirements)
    stmt = make_statement(fname, a_sha, sha256(sbom), builder_id, tree_digest(src_dir))
    env = sign_envelope(_canon(stmt), PAYLOAD_TYPE, signers)
    idx, sth = tlog.append(log_entry(a_sha, env))
    proof = [p.hex() for p in tlog.inclusion_proof(idx, sth["tree_size"])]
    return artifact, Bundle(env, sbom, {"index": idx, "sth": sth, "proof": proof})


@dataclass
class Policy:
    trusted_keys: dict                  # keyid -> 32 байта Ed25519
    threshold: int
    tlog_public_key: bytes
    allowed_builders: set = field(default_factory=set)
    blocked_components: set = field(default_factory=set)   # {(name, version)}
    min_log_size: int = 0               # защита от отката: не принимать STH меньше уже виденного
    require_algs: tuple = ()            # напр. ("ed25519", "ml-dsa-65") - гибридная подпись обязательна


def verify_release(artifact: bytes, b: Bundle, policy: Policy, rebuild_src: str | None = None, name_prefix: str | None = None):
    """Бросает ReleaseRejected при любом несоответствии. Возвращает statement."""
    try:
        payload = verify_envelope(b.envelope, policy.trusted_keys, policy.threshold, PAYLOAD_TYPE, policy.require_algs)
    except DsseError as e:
        raise ReleaseRejected(f"подпись: {e}")
    try:
        st = json.loads(payload)
        subj, = st["subject"]
        a_sha = subj["digest"]["sha256"]
        builder = st["predicate"]["runDetails"]["builder"]["id"]
        sbom_sha = st["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["sha256"]
        if st["_type"] != STATEMENT_TYPE or st["predicateType"] != PROVENANCE_TYPE:
            raise ReleaseRejected("неожиданный тип statement")
    except (KeyError, ValueError, TypeError, IndexError, json.JSONDecodeError) as e:
        raise ReleaseRejected(f"битый provenance: {e}")
    if sha256(artifact) != a_sha:
        raise ReleaseRejected("хэш артефакта не совпадает с подписанным в provenance")
    if sha256(b.sbom) != sbom_sha:
        raise ReleaseRejected("SBOM не совпадает с подписанным в provenance")
    if policy.allowed_builders and builder not in policy.allowed_builders:
        raise ReleaseRejected(f"недоверенный builder {builder}")
    try:
        bad = components(b.sbom) & policy.blocked_components
    except SbomError as e:
        raise ReleaseRejected(str(e))
    if bad:
        raise ReleaseRejected(f"в SBOM запрещённые компоненты: {sorted(bad)}")
    # прозрачность: запись о ЭТОМ артефакте и ЭТОМ конверте включена в подписанное дерево
    try:
        sth, idx = b.log["sth"], b.log["index"]
        if not verify_sth_signature(Ed25519PublicKey.from_public_bytes(policy.tlog_public_key), sth):
            raise ReleaseRejected("подпись STH журнала недействительна")
        if sth["tree_size"] < policy.min_log_size:
            raise ReleaseRejected("STH старее уже виденного (откат журнала)")
        proof = [bytes.fromhex(x) for x in b.log["proof"]]
        if not merkle.verify_inclusion(log_entry(a_sha, b.envelope), idx, sth["tree_size"], proof,
                                       bytes.fromhex(sth["root_hash"])):
            raise ReleaseRejected("нет доказательства включения в журнал")
    except (KeyError, ValueError, TypeError) as e:
        raise ReleaseRejected(f"битые данные журнала: {e}")
    if rebuild_src is not None:
        if subj["name"].endswith(".whl"):
            m = re.match(r"^(.+?)-([^-]+)-py3-none-any\.whl$", subj["name"])
            if not m:
                raise ReleaseRejected("нестандартное имя wheel")
            reqs = [c for c in components_requires(b.sbom)]
            rebuilt = build_wheel(rebuild_src, m.group(1), m.group(2), reqs)
        else:
            prefix = name_prefix or subj["name"].removesuffix(".tar.gz") + "/"
            rebuilt = deterministic_targz(rebuild_src, prefix=prefix)
        if sha256(rebuilt) != a_sha:
            raise ReleaseRejected("пересборка из исходников даёт другой артефакт (не воспроизводимо / подмена)")
    return st
