"""vtotp.__main__（`python -m vtotp` エントリーポイント）の単体テスト。"""

from __future__ import annotations

import pytest

from vtotp.__main__ import main


class TestMain:
    """main関数に関するテスト。"""

    def test_returns_exit_code_from_explicit_argv(self) -> None:
        """明示的に渡したargvに基づく終了コードが返されることを確認する。"""
        assert main(["--version"]) == 0

    def test_uses_sys_argv_when_argv_is_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """argv省略時にsys.argvが使用されることを確認する。"""
        monkeypatch.setattr("sys.argv", ["vtotp", "--version"])
        assert main() == 0

    def test_parse_error_returns_exit_code_2(self) -> None:
        """不正な引数の場合、終了コード2が返されることを確認する。"""
        assert main(["list", "--no-such-option"]) == 2
