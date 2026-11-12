"""Exercise the actual exact-head review and sensitive-path decisions."""

import copy

import pytest

from scripts import pr_policy as policy

BASE = "a" * 40
HEAD = "b" * 40


def snapshot(path="README.md"):
    pr = {
        "number": 1,
        "state": "open",
        "draft": False,
        "base": {"sha": BASE, "ref": "main", "repo": {"full_name": policy.REPOSITORY}},
        "head": {"sha": HEAD},
        "user": {"login": "contributor"},
        "mergeable": True,
        "mergeable_state": "clean",
        "changed_files": 1,
    }
    reviews = [
        {
            "id": 10,
            "user": {"id": 351676210, "login": "ecomwizards-gandalf[bot]", "type": "Bot"},
            "state": "APPROVED",
            "commit_id": HEAD,
        }
    ]
    runs = [
        {
            "id": index,
            "name": name,
            "head_sha": HEAD,
            "app": {"id": 15368},
            "status": "completed",
            "conclusion": "success",
        }
        for index, name in enumerate(("checks", "public-content"), 1)
    ]
    statuses = [
        {"id": 20, "context": "review", "state": "success", "creator": {"login": "github-actions[bot]", "type": "Bot"}}
    ]
    comparison = {
        "base_commit": {"sha": BASE},
        "merge_base_commit": {"sha": BASE},
        "status": "ahead",
        "files": [{"filename": path}],
    }
    return pr, reviews, runs, statuses, comparison


def test_current_independent_approval_and_green_docs_change_is_eligible():
    assert policy.merge_decision(*snapshot()) == (True, "eligible")


@pytest.mark.parametrize(
    "path",
    [
        "privilege_broker/pve/authorization.py",
        "tests/test_pve_policy.py",
        ".github/workflows/release-please.yml",
        "scripts/pr_policy.py",
        "pyproject.toml",
        "uv.lock",
        "LICENSE",
        "AGENTS.md",
        "unknown.md",
    ],
)
def test_executable_and_unknown_paths_require_human_merge(path):
    assert policy.merge_decision(*snapshot(path)) == (False, "sensitive_paths")


def test_stale_approval_cannot_be_relabelled_as_current():
    values = snapshot()
    values[1][0]["commit_id"] = BASE
    assert policy.merge_decision(*values) == (False, "current_head_approval_required")


def test_changes_requested_after_approval_revokes_it():
    values = snapshot()
    rejection = copy.deepcopy(values[1][0])
    rejection.update(id=11, state="CHANGES_REQUESTED")
    values[1].append(rejection)
    assert policy.merge_decision(*values) == (False, "changes_requested")


def test_lookalike_reviewer_cannot_approve():
    values = snapshot()
    values[1][0]["user"]["id"] = 99
    assert policy.merge_decision(*values) == (False, "current_head_approval_required")


def test_author_cannot_self_approve_even_as_the_configured_identity():
    values = snapshot()
    values[0]["user"]["login"] = "ecomwizards-gandalf[bot]"
    assert policy.merge_decision(*values) == (False, "current_head_approval_required")


def test_old_head_ci_is_not_current_ci():
    values = snapshot()
    values[2][0]["head_sha"] = BASE
    assert policy.merge_decision(*values) == (False, "check_head_mismatch")


def test_a_red_required_check_blocks_merge():
    values = snapshot()
    values[2][0]["conclusion"] = "failure"
    assert policy.merge_decision(*values) == (False, "required_check_not_success")


def test_renaming_sensitive_source_into_docs_stays_sensitive():
    values = snapshot("docs/architecture.md")
    values[4]["files"][0]["previous_filename"] = "privilege_broker/pve/authorization.py"
    assert policy.merge_decision(*values) == (False, "sensitive_paths")


def test_incomplete_comparison_cannot_admit_a_merge():
    values = snapshot()
    values[0]["changed_files"] = 2
    assert policy.merge_decision(*values) == (False, "incomplete_changed_files")


def test_changed_base_or_head_invalidates_the_snapshot():
    before = snapshot()[0]
    after = copy.deepcopy(before)
    after["base"]["sha"] = "c" * 40
    assert not policy.same_refs(before, after)
    after = copy.deepcopy(before)
    after["head"]["sha"] = "d" * 40
    assert not policy.same_refs(before, after)
