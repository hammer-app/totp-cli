"""vtotp アプリケーション全体で使用する例外クラス階層を定義するモジュール。

すべての例外は :class:`TotpCliError` を基底クラスとして派生し、
``CliHandler`` が終了コードへ変換できるよう ``exit_code`` 属性を持つ。

DESIGN.md 21章「ドメイン例外と表示層の連携」に基づき、例外は表示文
（ローカライズ済み文字列）を直接保持せず、代わりに型安全な
:class:`~vtotp.i18n.catalog.MsgKey` と、秘密情報を含まない構造化コンテキスト
（パス名・サービス名等の文字列のみ）を保持する。実際の言語別メッセージへの
変換は表示層（``vtotp.cli.formatter``）が ``context`` を使って行う。これにより
core/domain層は表示言語に一切依存しない（Zero Leakage Rule）。
"""

from __future__ import annotations

from typing import Mapping

from vtotp.i18n.catalog import MsgKey


class TotpCliError(Exception):
    """vtotp アプリケーション共通の基底例外。

    秘密情報を含まない、型安全なメッセージキーと構造化コンテキストのみを
    保持する。``context`` の値には鍵バイト列・TOTPシークレット・復号済み
    JSON等を含めてはならない（パス名・サービス名・バージョン番号等の
    安全な文字列のみを許容する）。
    """

    #: このエラー種別に対応するCLI終了コード（既定値は一般エラー）。
    exit_code: int = 1

    def __init__(
        self,
        message_key: MsgKey,
        context: Mapping[str, str] | None = None,
    ) -> None:
        """メッセージキーと安全なコンテキストを保持して初期化する。"""
        self.message_key: MsgKey = message_key
        self.context: Mapping[str, str] = dict(context) if context is not None else {}
        super().__init__(message_key.value)


class KeyNotFoundError(TotpCliError):
    """解決された鍵パスに鍵ファイルが存在しない場合に送出される例外。"""

    exit_code: int = 3


class InvalidKeyError(TotpCliError):
    """鍵ファイルのサイズや形式が不正な場合に送出される例外。"""

    exit_code: int = 3


class StorageCorruptedError(TotpCliError):
    """暗号化データファイルが破損している、または復号に失敗した場合の例外。"""

    exit_code: int = 4


class ServiceNotFoundError(TotpCliError):
    """指定されたサービス名が登録済みデータに存在しない場合の例外。"""

    exit_code: int = 5


class InvalidSecretError(TotpCliError):
    """TOTPシークレットの形式（Base32等）が不正な場合に送出される例外。"""

    exit_code: int = 6


class CommandParseError(TotpCliError):
    """CLI引数の解析に失敗した場合に送出される例外。"""

    exit_code: int = 2


class CancelledError(TotpCliError):
    """対話確認（上書き警告・ローテーション上限警告等）でユーザーが操作を中止した場合の例外。"""

    exit_code: int = 7
