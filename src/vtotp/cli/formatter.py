"""CLIコマンドの出力フォーマット・多言語メッセージ解決を担うモジュール。

CLAUDE.md「出力ストリーム」規約に基づき、``stdout`` はコマンドの結果
データ（生のTOTPコード、サービス一覧など）専用とし、``stderr`` は
利用者向けの案内・警告・エラーメッセージ専用とする。

DESIGN.md 19.3「表示とZero Leakage」に基づき、表示層は
:class:`~vtotp.i18n.catalog.MsgKey` と安全な表示コンテキストのみを受け取り、
言語別カタログを介してローカライズ済みメッセージを解決する。秘密情報
（鍵バイト列・TOTPシークレット・復号済みJSON等）はいかなる出力にも
含めてはならない（Zero Leakage Rule）。
"""

from __future__ import annotations

import sys
from typing import IO, Sequence

from vtotp.domain.exceptions import TotpCliError
from vtotp.domain.models import SecretRecord
from vtotp.i18n.catalog import MsgKey, get_catalog


def format_message(key: MsgKey, language: str, **context: str) -> str:
    """`key`と`language`からローカライズ済みメッセージを解決する。

    `context`には秘密情報を含まない安全な表示値（パス名・サービス名等）
    のみを渡す。
    """
    template = get_catalog(language)[key]
    return template.format(**context)


def format_error(error: TotpCliError, language: str) -> str:
    """例外の`message_key`/`context`をローカライズし、ラベル付きのエラー表示文を返す。"""
    label = format_message(MsgKey.LABEL_ERROR, language)
    body = format_message(error.message_key, language, **error.context)
    return f"{label}: {body}"


def format_warning(key: MsgKey, language: str, **context: str) -> str:
    """`key`をローカライズし、ラベル付きの警告表示文を返す。"""
    label = format_message(MsgKey.LABEL_WARNING, language)
    body = format_message(key, language, **context)
    return f"{label}: {body}"


def write_code(code: str, stream: IO[str] | None = None) -> None:
    """生成されたTOTPコードのみをstdoutへ出力する。"""
    print(code, file=stream if stream is not None else sys.stdout)


def format_service_table(records: Sequence[SecretRecord], language: str) -> str:
    """サービス名とissuerの対応表を整形した文字列として返す。

    シークレットの値は一切含めない（Zero Leakage Rule）。登録が無い
    場合は空文字列を返す。
    """
    if not records:
        return ""

    name_header = format_message(MsgKey.LIST_HEADER_SERVICE, language)
    issuer_header = format_message(MsgKey.LIST_HEADER_ISSUER, language)
    placeholder = format_message(MsgKey.LIST_NO_ISSUER_PLACEHOLDER, language)
    name_width = max(len(name_header), *(len(r.service_name) for r in records))
    lines = [f"{name_header.ljust(name_width)}  {issuer_header}"]
    for record in records:
        issuer = record.issuer if record.issuer else placeholder
        lines.append(f"{record.service_name.ljust(name_width)}  {issuer}")
    return "\n".join(lines)


def write_service_table(
    records: Sequence[SecretRecord],
    language: str,
    stream: IO[str] | None = None,
) -> None:
    """サービス一覧を表形式でstdoutへ出力する。シークレットは出力しない。"""
    table = format_service_table(records, language)
    if table:
        print(table, file=stream if stream is not None else sys.stdout)


def format_remaining_seconds_bar(
    remaining: int, time_step: int, width: int = 20
) -> str:
    """現在のTOTP有効期間の残り秒数を表す簡易プログレスバー文字列を生成する。"""
    if time_step <= 0:
        raise ValueError("time_step must be 1 or greater")
    if width <= 0:
        raise ValueError("width must be 1 or greater")

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


def write_info(
    key: MsgKey,
    language: str,
    *,
    stream: IO[str] | None = None,
    **context: str,
) -> None:
    """利用者向けの案内メッセージをローカライズしてstderrへ出力する。"""
    message = format_message(key, language, **context)
    print(message, file=stream if stream is not None else sys.stderr)


def write_warning(
    key: MsgKey,
    language: str,
    *,
    stream: IO[str] | None = None,
    **context: str,
) -> None:
    """警告メッセージをローカライズし、ラベル付きでstderrへ出力する。"""
    print(
        format_warning(key, language, **context),
        file=stream if stream is not None else sys.stderr,
    )


def write_error(
    error: TotpCliError,
    language: str,
    *,
    stream: IO[str] | None = None,
) -> None:
    """例外をローカライズし、ラベル付きのエラーメッセージとしてstderrへ出力する。

    秘密情報（鍵の内容やTOTPシークレット）は例外の`context`に含まれない
    前提であり、呼び出し元（core/domain層）がこの制約を守る責任を持つ
    （Zero Leakage Rule）。
    """
    print(
        format_error(error, language), file=stream if stream is not None else sys.stderr
    )
