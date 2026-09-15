"""vtotp.cli パッケージの公開インターフェース。

CLIエントリーポイント（:class:`CliHandler`）を外部モジュールへ公開する。
"""

from __future__ import annotations

from vtotp.cli.handler import CliHandler

__all__ = ["CliHandler"]
