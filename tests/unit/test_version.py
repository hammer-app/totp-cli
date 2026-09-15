"""totp_cli パッケージのバージョンメタデータに関する単体テスト。"""

from __future__ import annotations

import totp_cli


class TestVersion:
    """`totp_cli.__version__` に関するテスト。"""

    def test_version_matches_pyproject_toml(self) -> None:
        """`__version__` が `pyproject.toml` の `version`（0.1.3）と一致することを確認する。"""
        assert totp_cli.__version__ == "0.1.3"

    def test_version_is_exported_via_all(self) -> None:
        """`__version__` が `__all__` を通じて公開されていることを確認する。"""
        assert totp_cli.__all__ == ["__version__"]
        assert "__version__" in totp_cli.__all__
