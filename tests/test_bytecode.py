from intentscope.bytecode import _is_framework, _pretty


def test_pretty_class_name():
    assert _pretty("Lcom/example/Foo;") == "com.example.Foo"


def test_framework_prefixes_excluded():
    assert _is_framework("Landroidx/activity/ComponentActivity;")
    assert _is_framework("Lcom/google/android/gms/Foo;")
    assert not _is_framework("Lcom/authy/authy/activities/PinActivity;")
