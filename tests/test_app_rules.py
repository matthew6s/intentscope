from intentscope.models import Application, Component
from intentscope.rules import scan, scan_application


def _ids(fs): return sorted(f.rule_id for f in fs)


def test_debuggable_flags_is006():
    assert "IS006" in _ids(scan_application(Application(debuggable=True)))


def test_allowbackup_default_flags_is007():
    # unset => defaults to true => flagged
    assert "IS007" in _ids(scan_application(Application(allow_backup=None)))
    # explicitly false => not flagged
    assert "IS007" not in _ids(scan_application(Application(allow_backup=False)))


def test_cleartext_flags_is008():
    assert "IS008" in _ids(scan_application(Application(uses_cleartext_traffic=True)))


def test_exported_provider_grant_uri_flags_is005():
    c = Component("provider", ".P", exported=True, permission=None, grant_uri_permissions=True)
    assert "IS005" in _ids(scan([c] and Application(allow_backup=False), [c]))


def test_provider_with_permission_is_clean_of_is005():
    c = Component("provider", ".P", exported=True, permission="x.PERM", grant_uri_permissions=True)
    assert "IS005" not in _ids(scan(Application(allow_backup=False), [c]))
