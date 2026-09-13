"""CLIコマンドの出力フォーマットを担うモジュール。

CLAUDE.md「出力ストリーム」規約に基づき、``stdout`` はコマンドの結果
データ（生のTOTPコード、サービス一覧など）専用とし、``stderr`` は
利用者向けの案内・警告・エラーメッセージ専用とする。いずれの出力にも
TOTPシークレットや鍵の内容を含めてはならない（Zero Leakage Rule）。
"""

from __future__ import annotations

import sys
from typing import IO, Sequence

from totp_cli.domain.models import SecretRecord


def write_code(code: str, stream: IO[str] | None = None) -> None:
    """生成されたTOTPコードのみをstdoutへ出力する。"""
    print(code, file=stream if stream is not None else sys.stdout)


def format_service_table(records: Sequence[SecretRecord]) -> str:
    """サービス名とissuerの対応表を整形した文字列として返す。

    シークレットの値は一切含めない（Zero Leakage Rule）。登録が無い
    場合は空文字列を返す。
    """
    if not records:
        return ""

    name_header = "SERVICE"
    issuer_header = "ISSUER"
    name_width = max(len(name_header), *(len(r.service_name) for r in records))
    lines = [f"{name_header.ljust(name_width)}  {issuer_header}"]
    for record in records:
        issuer = record.issuer if record.issuer else "-"
        lines.append(f"{record.service_name.ljust(name_width)}  {issuer}")
    return "\n".join(lines)


def write_service_table(
    records: Sequence[SecretRecord], stream: IO[str] | None = None
) -> None:
    """サービス一覧を表形式でstdoutへ出力する。シークレットは出力しない。"""
    table = format_service_table(records)
    if table:
        print(table, file=stream if stream is not None else sys.stdout)


def format_remaining_seconds_bar(
    remaining: int, time_step: int, width: int = 20
) -> str:
    """現在のTOTP有効期間の残り秒数を表す簡易プログレスバー文字列を生成する。"""
    if time_step <= 0:
        raise ValueError("time_stepは1以上である必要があります")
    if width <= 0:
        raise ValueError("widthは1以上である必要があります")

    clamped_remaining = max(0, min(remaining, time_step))
    filled = round((clamped_remaining / time_step) * width)
    filled = max(0, min(filled, width))
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {clamped_remaining:>2d}s"


def write_remaining_seconds_bar(
    remaining: int,
    time_step: int,
    stream: IO[str] | None = None,
) -> None:
    """残り有効秒数バーをstderrへ出力する（装飾情報のためstdoutには出力しない）。"""
    bar = format_remaining_seconds_bar(remaining, time_step)
    print(bar, file=stream if stream is not None else sys.stderr)


def write_info(message: str, stream: IO[str] | None = None) -> None:
    """利用者向けの案内メッセージをstderrへ出力する。"""
    print(message, file=stream if stream is not None else sys.stderr)


def write_warning(message: str, stream: IO[str] | None = None) -> None:
    """警告メッセージをstderrへ出力する。"""
    print(f"警告: {message}", file=stream if stream is not None else sys.stderr)


def write_error(message: str, stream: IO[str] | None = None) -> None:
    """エラーメッセージをstderrへ出力する。

    秘密情報（鍵の内容やTOTPシークレット）を含めてはならない
    （Zero Leakage Rule）。呼び出し元がこの制約を守る責任を持つ。
    """
    print(f"エラー: {message}", file=stream if stream is not None else sys.stderr)
