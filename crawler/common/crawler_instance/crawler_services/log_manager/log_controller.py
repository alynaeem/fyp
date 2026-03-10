import sys
from datetime import datetime


class _Logger:
    """
    Simple logger compatible with existing crawler scripts:
      log.g().e("error")
      log.g().i("info")
    """

    def e(self, message: str):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[ERROR {ts}] {message}", file=sys.stderr)

    def i(self, message: str):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[INFO  {ts}] {message}")


class log:
    """
    Static access wrapper to match usage:
      log.g().e(...)
      log.g().i(...)
    """

    @staticmethod
    def g() -> _Logger:
        return _Logger()
