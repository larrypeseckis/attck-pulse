"""MITRE ATT&CK technique loader.

Pulls the Enterprise ATT&CK STIX bundle for the version pinned in settings
and populates the techniques table.

We use the mitreattack-python library to parse the STIX bundle. The bundle is
~10MB and downloaded on demand. For air-gapped reproduction, swap the URL
fetch for a local file load.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import httpx
from mitreattack.stix20 import MitreAttackData
from sqlalchemy import text

from threat_intel.config import settings
from threat_intel.db import session_scope
from threat_intel.logging_setup import get_logger

logger = get_logger(__name__)


def download_bundle(url: str, dest: Path) -> None:
    """Download the STIX bundle to dest."""
    logger.info("Downloading ATT&CK bundle: %s", url)
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
    dest.write_bytes(response.content)
    logger.info("Downloaded %d bytes to %s", len(response.content), dest)


def load_techniques(bundle_path: Path) -> list[dict]:
    """Parse the STIX bundle and return technique records."""
    attack_data = MitreAttackData(str(bundle_path))
    techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

    records: list[dict] = []
    for technique in techniques:
        # Each technique has external_references; the first ATT&CK ref is the canonical id
        attack_id = None
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                break
        if attack_id is None:
            continue

        is_subtechnique = bool(technique.get("x_mitre_is_subtechnique", False))
        parent_id: str | None = None
        if is_subtechnique and "." in attack_id:
            parent_id = attack_id.split(".")[0]

        # Tactics come from kill_chain_phases
        tactics = [
            phase.get("phase_name", "")
            for phase in technique.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        primary_tactic = tactics[0] if tactics else None

        records.append(
            {
                "technique_id": attack_id,
                "name": technique.get("name", ""),
                "tactic": primary_tactic,
                "description": technique.get("description", ""),
                "is_subtechnique": is_subtechnique,
                "parent_technique": parent_id,
                "attack_version": settings.attack_version,
            }
        )

    return records


def upsert_techniques(records: list[dict]) -> tuple[int, int]:
    """Insert techniques. Parents must be inserted before sub-techniques.

    Returns (parents_inserted, subtechniques_inserted).
    """
    parents = [r for r in records if not r["is_subtechnique"]]
    subs = [r for r in records if r["is_subtechnique"]]

    logger.info("Loading %d parent techniques and %d sub-techniques", len(parents), len(subs))

    upsert_sql = text(
        """
        INSERT INTO techniques (
            technique_id, name, tactic, description,
            is_subtechnique, parent_technique, attack_version
        )
        VALUES (
            :technique_id, :name, :tactic, :description,
            :is_subtechnique, :parent_technique, :attack_version
        )
        ON CONFLICT (technique_id) DO UPDATE SET
            name = EXCLUDED.name,
            tactic = EXCLUDED.tactic,
            description = EXCLUDED.description,
            is_subtechnique = EXCLUDED.is_subtechnique,
            parent_technique = EXCLUDED.parent_technique,
            attack_version = EXCLUDED.attack_version,
            loaded_at = NOW()
        """
    )

    with session_scope() as session:
        for record in parents:
            session.execute(upsert_sql, record)
        for record in subs:
            session.execute(upsert_sql, record)

    return len(parents), len(subs)


def run() -> None:
    """Top-level: download, parse, store."""
    with tempfile.TemporaryDirectory() as tmp:
        bundle_file = Path(tmp) / "enterprise-attack.json"
        download_bundle(settings.attack_bundle_url, bundle_file)

        # Validate the bundle parses as JSON before handing to mitreattack
        try:
            json.loads(bundle_file.read_text())
        except json.JSONDecodeError as err:
            raise RuntimeError(f"Bundle is not valid JSON: {err}") from err

        records = load_techniques(bundle_file)
        if not records:
            raise RuntimeError("No techniques parsed from bundle")

        parents_count, subs_count = upsert_techniques(records)

    logger.info(
        "ATT&CK load complete: version=%s parents=%d subs=%d total=%d",
        settings.attack_version,
        parents_count,
        subs_count,
        parents_count + subs_count,
    )
