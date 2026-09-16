"""vtotp.__main__（`python -m vtotp` エントリーポイント）の単体テスト。"""

from __future__ import annotations

import pytest

from vtotp.__main__ import _reconfigure_stdio_utf8, main


class _RaisingStream:
    """``reconfigure``呼び出し時に指定した例外を送出するダミーストリーム。"""

    def __init__(self, exc_type: type[BaseException]) -> None:
        self._exc_type = exc_type

    def reconfigure(self, *, encoding: str) -> None:
        raise self._exc_type(f"reconfigure failed: {encoding}")


class _NoReconfigureStream:
    """``reconfigure``属性を持たないダミーストリーム。"""


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


class TestReconfigureStdioUtf8:
    """``_reconfigure_stdio_utf8``関数に関するテスト。"""

    @pytest.mark.parametrize("exc_type", [ValueError, OSError])
    def test_swallows_reconfigure_errors(
        self, monkeypatch: pytest.MonkeyPatch, exc_type: type[BaseException]
    ) -> None:
        """reconfigure呼び出し時にValueError/OSErrorが送出されても握りつぶすことを確認する。"""
        monkeypatch.setattr("sys.stdout", _RaisingStream(exc_type))
        monkeypatch.setattr("sys.stderr", _RaisingStream(exc_type))

        _reconfigure_stdio_utf8()

    def test_skips_stream_without_reconfigure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``reconfigure``を持たないストリームに対しては何もしないことを確認する。"""
        monkeypatch.setattr("sys.stdout", _NoReconfigureStream())
        monkeypatch.setattr("sys.stderr", _NoReconfigureStream())

        _reconfigure_stdio_utf8()
