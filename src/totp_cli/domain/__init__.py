"""totp_cli.domain パッケージの公開インターフェース。

ドメインモデルおよび例外クラスを外部モジュールへ公開する。
"""

from __future__ import annotations

from totp_cli.domain.exceptions import (
    CommandParseError,
    InvalidKeyError,
    InvalidSecretError,
    KeyNotFoundError,
    ServiceNotFoundError,
    StorageCorruptedError,
    TotpCliError,
)
from totp_cli.domain.models import AppConfig, EncryptedPayload, SecretRecord

__all__ = [
    "TotpCliError",
    "KeyNotFoundError",
    "InvalidKeyError",
    "StorageCorruptedError",
    "ServiceNotFoundError",
    "InvalidSecretError",
    "CommandParseError",
    "SecretRecord",
    "AppConfig",
    "EncryptedPayload",
]
