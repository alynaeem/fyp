import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator import _run_leaks


if __name__ == "__main__":
    os.environ["LEAK_SITES_ONLY"] = "1"
    os.environ.setdefault("LEAK_STATUS_FILTER", "not_run,error,unreachable,empty")
    _run_leaks()
