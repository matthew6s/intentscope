from intentscope.models import Component, IntentFilter
from intentscope.rules import scan_components


def _bf(scheme, host="h.example.com", auto=False):
    return IntentFilter(
        actions=["android.intent.action.VIEW"],
        categories=["android.intent.category.BROWSABLE"],
        schemes=[scheme], hosts=[host], auto_verify=auto,
    )


def _ids(findings):
    return sorted(f.rule_id for f in findings)


def test_unverified_web_link_flags_is001():
    c = Component("activity", ".A", exported=True, permission=None, intent_filters=[_bf("https")])
    assert "IS001" in _ids(scan_components([c]))


def test_autoverify_web_link_is_clean_of_is001():
    c = Component("activity", ".A", exported=True, permission=None,
                  intent_filters=[_bf("https", auto=True)])
    assert "IS001" not in _ids(scan_components([c]))


def test_custom_scheme_flags_is002():
    c = Component("activity", ".A", exported=True, permission=None, intent_filters=[_bf("myapp")])
    assert "IS002" in _ids(scan_components([c]))


def test_exported_service_no_permission_flags_is003():
    c = Component("service", ".S", exported=True, permission=None)
    assert _ids(scan_components([c])) == ["IS003"]


def test_permission_guard_suppresses_is003():
    c = Component("service", ".S", exported=True, permission="com.x.PERM")
    assert scan_components([c]) == []


def test_not_exported_is_clean():
    c = Component("activity", ".A", exported=False, permission=None, intent_filters=[_bf("https")])
    assert scan_components([c]) == []


def test_implicit_export_via_intent_filter_flags_is003():
    # exported unset + has intent-filter => implicitly exported (API < 31)
    c = Component("activity", ".A", exported=None, permission=None, intent_filters=[_bf("https")])
    ids = _ids(scan_components([c]))
    assert "IS001" in ids and "IS003" in ids


def test_singletask_deeplink_flags_is004():
    c = Component("activity", ".A", exported=True, permission=None,
                  intent_filters=[_bf("https", auto=True)], launch_mode="singleTask")
    assert "IS004" in _ids(scan_components([c]))
