"""DarkPulse FastAPI application loader.

The backend implementation is split into ordered chunks under backend/modules.
Each chunk is executed in this module's globals so existing route decorators,
shared state, collection handles, and helper names keep their original behavior.
"""

from __future__ import annotations

import json
import pathlib

_BACKEND_MODULE_DIR = pathlib.Path(__file__).resolve().parent / "backend" / "modules"
_BACKEND_MANIFEST = _BACKEND_MODULE_DIR / "manifest.json"


def _load_backend_modules() -> None:
    module_names = json.loads(_BACKEND_MANIFEST.read_text())
    for module_name in module_names:
        module_path = _BACKEND_MODULE_DIR / module_name
        code = compile(module_path.read_text(), str(module_path), "exec")
        exec(code, globals())


_load_backend_modules()
