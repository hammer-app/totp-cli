"""``python -m totp_cli`` で起動するためのエントリーポイント。"""

from __future__ import annotations

import sys

from totp_cli.cli.handler import CliHandler


def _reconfigure_stdio_utf8() -> None:
    """標準出力・標準エラー出力のエンコーディングをUTF-8へ再設定する。

    Windowsの既定コードページ（cp1252等）の端末では、日本語のヘルプ
    メッセージ等を表示しようとした際に``UnicodeEncodeError``が発生し
    うるため、起動時にエンコーディングをUTF-8へ固定する。テスト時の
    差し替えストリーム等、``reconfigure``を持たない・失敗するストリーム
    に対しては何もしない。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    """CliHandlerを実行し、終了コードを返す。"""
    _reconfigure_stdio_utf8()
    handler = CliHandler()
    return handler.run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
