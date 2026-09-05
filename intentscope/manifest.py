"""Load an AndroidManifest from a decoded .xml file or from an .apk.

The .xml path uses only the standard library, so the tool (and its tests)
run with no third-party dependencies. The .apk path lazily imports
androguard, which is only required when scanning a binary APK.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from .models import Application, Component, IntentFilter

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def _attr(el: ET.Element, name: str) -> Optional[str]:
    return el.get(f"{{{_ANDROID_NS}}}{name}")


def _bool_attr(el: ET.Element, name: str) -> Optional[bool]:
    v = _attr(el, name)
    if v is None:
        return None
    return str(v).lower() == "true"


def _parse_intent_filter(el: ET.Element) -> IntentFilter:
    f = IntentFilter(auto_verify=bool(_bool_attr(el, "autoVerify")))
    for action in el.findall("action"):
        n = _attr(action, "name")
        if n:
            f.actions.append(n)
    for cat in el.findall("category"):
        n = _attr(cat, "name")
        if n:
            f.categories.append(n)
    for data in el.findall("data"):
        s = _attr(data, "scheme")
        h = _attr(data, "host")
        if s:
            f.schemes.append(s)
        if h:
            f.hosts.append(h)
    return f


def parse_manifest_xml(root: ET.Element) -> tuple[Application, list[Component]]:
    app = root.find("application")
    if app is None:
        return Application(), []
    application = Application(
        debuggable=_bool_attr(app, "debuggable"),
        allow_backup=_bool_attr(app, "allowBackup"),
        uses_cleartext_traffic=_bool_attr(app, "usesCleartextTraffic"),
        network_security_config=_attr(app, "networkSecurityConfig"),
    )
    components: list[Component] = []
    for tag in _COMPONENT_TAGS:
        for el in app.findall(tag):
            name = _attr(el, "name") or "(unnamed)"
            comp = Component(
                kind=tag,
                name=name,
                exported=_bool_attr(el, "exported"),
                permission=_attr(el, "permission"),
                launch_mode=_attr(el, "launchMode"),
                grant_uri_permissions=_bool_attr(el, "grantUriPermissions"),
            )
            for if_el in el.findall("intent-filter"):
                comp.intent_filters.append(_parse_intent_filter(if_el))
            components.append(comp)
    return application, components


def load_from_xml(path: str) -> tuple[Application, list[Component]]:
    tree = ET.parse(path)
    return parse_manifest_xml(tree.getroot())


def load_from_apk(path: str) -> tuple[Application, list[Component]]:
    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:  # pragma: no cover - exercised only with androguard absent
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "Scanning an .apk requires androguard. Install it with "
                "'pip install androguard', or pass a decoded AndroidManifest.xml."
            ) from exc
    apk = APK(path)
    xml_obj = apk.get_android_manifest_xml()
    return parse_manifest_xml(xml_obj)


def load_components(path: str) -> tuple[Application, list[Component]]:
    if path.lower().endswith(".apk"):
        return load_from_apk(path)
    return load_from_xml(path)
