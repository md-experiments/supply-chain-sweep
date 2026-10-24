from supply_chain_sweep.collectors import Context, docker
from supply_chain_sweep.collectors.docker import Image, packages_from_sbom, scan_images

SBOM = {"artifacts": [
    {"type": "python", "name": "litellm", "version": "1.82.8",
     "locations": [{"path": "/usr/lib/python3.12/site-packages/litellm-1.82.8.dist-info/METADATA"}],
     "metadata": {"files": [{"path": "litellm_init.pth", "digest": {"algorithm": "sha256",
                                                                    "value": "ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg"}}]}},
    {"type": "apk", "name": "musl", "version": "1.2"},
    {"type": "npm", "name": "left-pad", "version": "1.3.0", "locations": [{"path": "/app/node_modules/left-pad/package.json"}]},
]}


def test_packages_from_sbom():
    pkgs = packages_from_sbom(SBOM, Image("sha256:abc", ["app:latest"]))
    assert [(p.ecosystem.value, p.name, p.source_type.value) for p in pkgs] == [
        ("PyPI", "litellm", "image"), ("npm", "left-pad", "image")]
    assert pkgs[0].hashes == ["sha256:71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"]
    assert pkgs[0].container == "docker:app:latest"
    assert pkgs[0].files == ["litellm_init.pth"]


def test_missing_syft_is_a_warning(monkeypatch):
    ctx = Context()
    monkeypatch.setattr(docker, "list_images", lambda _ctx: [Image("sha256:abc", ["app:latest"])])
    monkeypatch.setattr(docker.shutil, "which", lambda name: None)
    pkgs, images = scan_images(ctx)
    assert pkgs == [] and len(images) == 1
    assert "install Syft" in ctx.warnings.items[0].message


def test_sbom_cache_used(monkeypatch):
    ctx = Context()
    monkeypatch.setattr(docker, "list_images", lambda _ctx: [Image("sha256:abc", ["app:latest"])])
    monkeypatch.setattr(docker.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(docker, "syft_sbom", lambda *a: (_ for _ in ()).throw(AssertionError("syft should not run")))
    pkgs, _ = scan_images(ctx, lambda _id: SBOM)
    assert len(pkgs) == 2
