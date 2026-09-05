import os
from intentscope.manifest import load_from_xml
from intentscope.rules import scan_components

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "AndroidManifest.xml")


def test_example_manifest_parses_and_flags_expected():
    _app, comps = load_from_xml(EXAMPLE)
    names = {c.name for c in comps}
    assert ".OpenUrlActivity" in names and ".ExportedSyncService" in names
    findings = scan_components(comps)
    ids = sorted(f.rule_id for f in findings)
    # the vulnerable components should trigger IS001/IS002/IS003; IS004 for singleTask
    assert "IS001" in ids and "IS002" in ids and "IS003" in ids and "IS004" in ids
    # the safe (autoVerify + not-exported) components must not create IS001 noise
    flagged = {(f.rule_id, f.component) for f in findings}
    assert ("IS001", ".VerifiedLinkActivity") not in flagged
    assert all(f.component != ".InternalActivity" for f in findings)
