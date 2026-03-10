# crawler/common/dev_signature.py
def developer_signature(name: str, note: str = "") -> str:
    base = f"{name}".strip()
    if note:
        return f"{base} :: {note}"
    return base
