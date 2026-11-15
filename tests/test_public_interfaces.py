"""The documented public interfaces import and start without deployment state.

Nothing here opens a socket, reads a private path or needs a credential.
"""

from __future__ import annotations

import importlib
import subprocess
import sys

import pytest

DOCUMENTED_MODULES = (
    "privilege_broker",
    "privilege_broker.notifications",
    "privilege_broker.pve.authorization",
    "privilege_broker.pve.bridge",
    "privilege_broker.pve.client",
    "privilege_broker.pve.common",
    "privilege_broker.pve.dispatcher",
    "privilege_broker.pve.service",
    "privilege_broker.pve.worker",
)


@pytest.mark.parametrize("name", DOCUMENTED_MODULES)
def test_documented_module_imports(name: str) -> None:
    assert importlib.import_module(name)


def test_dispatcher_cli_documents_its_configuration(tmp_path) -> None:
    # Isolated (-I) outside the checkout: proves the module entrypoint works
    # without the checkout on sys.path. This is a CLI smoke test, not proof the
    # built wheel installs; the clean-wheel check owns that claim.
    result = subprocess.run(
        [sys.executable, "-I", "-m", "privilege_broker.pve.dispatcher", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=tmp_path,
    )
    assert result.returncode == 0
    for flag in (
        "--policy",
        "--lease-public-key",
        "--claim-db",
        "--lxc-conf-dir",
        "--sudo-path",
        "--pct-path",
        "--command-timeout",
    ):
        assert flag in result.stdout
