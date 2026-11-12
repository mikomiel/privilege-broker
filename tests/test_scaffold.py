"""Check the bootstrap's publication and contributor-facing source contract."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_markdown_relative_links_resolve() -> None:
    pages = list(ROOT.glob("*.md")) + list((ROOT / "openspec").rglob("*.md")) + list((ROOT / "docs").rglob("*.md"))
    assert ROOT / "README.md" in pages
    checked = []
    for page in pages:
        for destination in re.findall(r"\[[^\]]*\]\(([^)]+)\)", page.read_text()):
            if "://" in destination or destination.startswith("#"):
                continue
            path = destination.split("#", 1)[0]
            target = (page.parent / path).resolve()
            assert target.is_relative_to(ROOT), (page, destination)
            assert target.is_file(), (page, destination)
            checked.append(target)
    assert ROOT / "LICENSE" in checked
    assert ROOT / "CONTRIBUTING.md" in checked


def test_project_licence_and_supported_python_are_explicit() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["license"] == "AGPL-3.0-only"
    assert project["requires-python"] == ">=3.11"
    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in (ROOT / "LICENSE").read_text()


def test_bootstrap_ci_has_no_write_authority() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "permissions:\n  contents: read\n" in workflow
    assert "pull_request:" in workflow
    assert "pull_request_target:" not in workflow
    assert "write" not in workflow
    assert "secrets." not in workflow
    assert "persist-credentials: false" in workflow
    assert "github.event.pull_request.head.sha || github.sha" in workflow
