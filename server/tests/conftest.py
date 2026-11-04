import pytest

from bearwatch import config, db


@pytest.fixture()
def session(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("BEARWATCH_DATABASE_URL", url)
    monkeypatch.setenv("BEARWATCH_API_TOKEN", "test-token")
    config.get_settings.cache_clear()
    db.init_db(url)
    with db.session_scope() as s:
        yield s
    config.get_settings.cache_clear()
