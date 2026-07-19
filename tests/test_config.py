import os

from domainrecon.config import load_env, save_secrets


def test_save_and_load_secrets_with_owner_only_permissions(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    save_secrets({"SHODAN_API_KEY": "key with spaces", "CENSYS_PAT": None}, path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert "key with spaces" in path.read_text()
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    load_env(path)
    assert os.environ["SHODAN_API_KEY"] == "key with spaces"


def test_rejects_multiline_secrets(tmp_path):
    try:
        save_secrets({"CENSYS_PAT": "bad\nvalue"}, tmp_path / ".env")
    except ValueError as exc:
        assert "CENSYS_PAT" in str(exc)
    else:
        raise AssertionError("multiline secret was accepted")
