"""totp_cli アプリケーション全体で使用する例外クラス階層を定義するモジュール。

すべての例外は :class:`TotpCliError` を基底クラスとして派生し、
``CliHandler`` が終了コードへ変換できるよう ``exit_code`` 属性を持つ。
例外メッセージには鍵ファイルの内容やTOTPシークレットなどの秘密情報を
含めてはならない（Zero Leakage Rule）。
"""

from __future__ import annotations


class TotpCliError(Exception):
    """totp-cli アプリケーション共通の基底例外。

    秘密情報を含まない、利用者向けのメッセージのみを保持する。
    """

    #: このエラー種別に対応するCLI終了コード（既定値は一般エラー）。
    exit_code: int = 1

    def __init__(self, message: str) -> None:
        """秘密情報を含まないエラーメッセージを保持して初期化する。"""
        super().__init__(message)


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
