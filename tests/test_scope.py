import pytest

from domainrecon.scope import Scope, normalize_domain


def test_normalizes_url_and_case():
    assert normalize_domain("HTTPS://WWW.Example.COM/path") == "www.example.com"


@pytest.mark.parametrize("bad", ["localhost", "127.0.0.1", "bad_domain.com", "-bad.example"])
def test_rejects_invalid_roots(bad):
    with pytest.raises(ValueError):
        normalize_domain(bad)


def test_scope_is_label_aware_and_honors_exclusions():
    scope = Scope.build(["example.com"], ["admin.example.com"])
    assert scope.contains("www.example.com")
    assert not scope.contains("notexample.com")
    assert not scope.contains("admin.example.com")
    assert not scope.contains("x.admin.example.com")
