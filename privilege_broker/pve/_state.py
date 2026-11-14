"""Private atomic JSON publication shared by the bridge and worker."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_state_json(path: Path, data: dict[str, Any]) -> None:
    """Publish complete, private JSON in an existing state directory.

    A failed write leaves any prior destination intact and removes only the
    temporary file created by this call. The caller owns directory creation.
    """
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as pending:
            temporary_path = Path(pending.name)
            json.dump(data, pending)
            pending.flush()
            os.fsync(pending.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
