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
    expressions = re.findall(r"\$\{\{(.*?)\}\}", workflow, re.DOTALL)
    assert not any(re.search(r"\bsecrets\s*(?:\.|\[)", expression) for expression in expressions)
    assert "persist-credentials: false" in workflow
    assert "github.event.pull_request.head.sha || github.sha" in workflow


def test_repository_workflow_requires_issues_and_distinguishes_pr_links() -> None:
    guide = " ".join((ROOT / "CONTRIBUTING.md").read_text().split())
    template = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text()
    instructions = (ROOT / "AGENTS.md").read_text()
    assert "including work covered by an active OpenSpec change" in guide
    assert "## Linked issues" in template
    for reference in ("Closes #<issue-number>", "Refs #<issue-number>"):
        assert reference in guide
        assert reference in template
    assert "[CONTRIBUTING.md](CONTRIBUTING.md)" in instructions
    assert "[SECURITY.md](SECURITY.md)" in guide


def test_unfinished_openspec_tasks_link_to_their_github_issues() -> None:
    changes = ROOT / "openspec" / "changes"
    assert list(changes.rglob("tasks.md")), "the task-document scan must reach a plan"
    for document in changes.glob("*/tasks.md"):
        for line in document.read_text().splitlines():
            if not line.startswith("- [ ] "):
                continue
            reference = re.search(
                r"\[Issue #(\d+)\]\(https://github\.com/mikomiel/privilege-broker/issues/(\d+)\)",
                line,
            )
            assert reference is not None, (document, line)
            assert reference.group(1) == reference.group(2), (document, line)
