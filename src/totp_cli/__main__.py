"""``python -m totp_cli`` で起動するためのエントリーポイント。"""

from __future__ import annotations

import sys

from totp_cli.cli.handler import CliHandler


def main(argv: list[str] | None = None) -> int:
    """CliHandlerを実行し、終了コードを返す。"""
    handler = CliHandler()
    return handler.run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
