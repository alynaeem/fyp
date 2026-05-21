from leak_collector.shared.generic_leak_snapshot import generic_leak_snapshot


class _csidb(generic_leak_snapshot):
    _instance = None
    SITE_NAME = "csidb"
    SITE_URL = "http://csidb.onion/"
    TEAM_NAME = "csidb"

