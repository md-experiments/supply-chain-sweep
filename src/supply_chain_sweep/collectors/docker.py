"""Local Docker images, inspected via a Syft SBOM without running them (FR-4, NFR-2)."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from ..models import Ecosystem, Package, SourceType
from ..util import normalize_digest
from . import Context

SYFT_TYPES = {"python": Ecosystem.PYPI, "npm": Ecosystem.NPM, "conda": Ecosystem.CONDA}


@dataclass
class Image:
    id: str
    tags: list[str]

    @property
    def label(self) -> str:
        return self.tags[0] if self.tags else self.id


def list_images(ctx: Context, docker: str = "docker") -> list[Image]:
    """All local images, tagged or not (docker image ls -a)."""
    if not shutil.which(docker):
        return []
    try:
        proc = subprocess.run(
            [docker, "image", "ls", "--all", "--no-trunc", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        ctx.warnings.add("docker", f"cannot list images: {exc}")
        return []
    if proc.returncode != 0:
        ctx.warnings.add("docker", f"cannot list images: {proc.stderr.strip()[:200]}")
        return []
    images: dict[str, Image] = {}
    for line in proc.stdout.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        image_id = row.get("ID", "")
        if not image_id:
            continue
        img = images.setdefault(image_id, Image(image_id, []))
        repo, tag = row.get("Repository", "<none>"), row.get("Tag", "<none>")
        if repo != "<none>":
            img.tags.append(f"{repo}:{tag}" if tag != "<none>" else repo)
    return [images[k] for k in sorted(images)]


def syft_sbom(image: Image, ctx: Context, syft: str = "syft") -> dict | None:
    try:
        proc = subprocess.run(
            [syft, "scan", f"docker:{image.id}", "-o", "syft-json", "-q"],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        ctx.warnings.add(image.label, f"syft failed: {exc}")
        return None
    if proc.returncode != 0:
        ctx.warnings.add(image.label, f"syft failed: {proc.stderr.strip()[:200]}")
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        ctx.warnings.add(image.label, "syft produced invalid JSON")
        return None


def packages_from_sbom(sbom: dict, image: Image) -> list[Package]:
    out = []
    for art in sbom.get("artifacts", []):
        eco = SYFT_TYPES.get(art.get("type", ""))
        if not eco or not art.get("name") or not art.get("version"):
            continue
        locs = art.get("locations") or [{}]
        path = locs[0].get("path", "")
        hashes = []
        for f in (art.get("metadata") or {}).get("files") or []:
            dg = f.get("digest") or {}
            if dg.get("algorithm") and dg.get("value"):
                d = normalize_digest(f"{dg['algorithm']}:{dg['value']}")
                if d:
                    hashes.append(d)
        integrity = (art.get("metadata") or {}).get("integrity")
        if isinstance(integrity, str):
            hashes += [d for d in (normalize_digest(i) for i in integrity.split()) if d]
        out.append(
            Package(
                ecosystem=eco,
                name=art["name"],
                version=art["version"],
                source_type=SourceType.IMAGE,
                location=f"{image.label}:{path}" if path else image.label,
                container=f"docker:{image.label}",
                hashes=hashes,
                files=[f.get("path", "") for f in (art.get("metadata") or {}).get("files") or [] if f.get("path")],
                extra={"image_id": image.id},
            )
        )
    return out


def scan_images(
    ctx: Context,
    sbom_cache_get: Callable[[str], dict | None] = lambda _id: None,
    sbom_cache_put: Callable[[str, dict], None] = lambda _id, _s: None,
) -> tuple[list[Package], list[Image]]:
    images = list_images(ctx)
    if not images:
        return [], []
    if not shutil.which("syft"):
        ctx.warnings.add(
            "docker",
            f"{len(images)} image(s) not inspected: install Syft (https://github.com/anchore/syft) to scan images",
        )
        return [], images
    out = []
    for img in images:
        sbom = sbom_cache_get(img.id)  # image IDs are content hashes, so SBOMs never go stale
        if sbom is None:
            sbom = syft_sbom(img, ctx)
            if sbom is not None:
                sbom_cache_put(img.id, sbom)
        if sbom:
            out += packages_from_sbom(sbom, img)
    return out, images
