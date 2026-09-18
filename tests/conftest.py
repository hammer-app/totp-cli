"""vtotpテストスイート全体で共有するpytest fixture。

テスト実行環境のOSロケール（日本語環境等）や、開発者・CIランナーの
シェルにたまたま設定された ``VTOTP_LANG``/``LANG``/``LC_ALL``/
``LC_MESSAGES`` に依存して、英語出力を期待するテストが環境依存で失敗する
ことを防ぐため、全テストの既定環境を毎回隔離する。

明示的に日本語（``ja``）を検証したいテストは、各テスト内で
``monkeypatch.setenv(ENV_LANG_VARIABLE, "ja")`` を呼び出す、または
:func:`locale.getlocale`/:func:`locale.setlocale` を独自にモックすること
で、この既定の隔離を上書きできる（`monkeypatch` はテストごとに独立した
スタックのため、後から行った `setattr`/`setenv` が優先される）。
"""

from __future__ import annotations

import locale

import pytest


@pytest.fixture(autouse=True)
def _isolate_language_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """全テストの既定言語環境を英語（`en`）へ隔離するautouse fixture。

    ``VTOTP_LANG``/``LANG``/``LC_ALL``/``LC_MESSAGES``環境変数を除去し、
    ``locale.getlocale``/``locale.setlocale``をOSロケール未設定
    （``(None, None)``相当）を返すよう差し替える。これにより
    ``vtotp.i18n.resolver.detect_os_locale()``は、テストがCLI引数や
    環境変数を明示的に指定しない限り常に``None``を返し、最終的に
    ``DEFAULT_LANGUAGE``（``en``）へ解決される。
    """
    for variable in ("VTOTP_LANG", "LANG", "LC_ALL", "LC_MESSAGES"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(locale, "getlocale", lambda *args, **kwargs: (None, None))
    monkeypatch.setattr(locale, "setlocale", lambda *args, **kwargs: "C")
