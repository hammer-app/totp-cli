"""totp_cli のドメインモデル（不変データ構造）を定義するモジュール。

DESIGN.md 5章で定義された ``SecretRecord``、``AppConfig``、
``EncryptedPayload`` を dataclass として実装する。いずれも不変
（``frozen=True``）とし、意図しない書き換えを防ぐ。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True, repr=False)
class SecretRecord:
    """1件のTOTPサービス登録情報を表す不変のドメインモデル。

    ``secret`` にはBase32形式のTOTPシークレットを保持するため、
    文字列表現に生の値を含めないよう ``__repr__`` を独自定義する
    （Zero Leakage Rule）。
    """

    service_name: str
    secret: str
    issuer: str | None = None

    def __repr__(self) -> str:
        """シークレットを含まない安全な文字列表現を返す。"""
        return (
            f"{self.__class__.__name__}(service_name={self.service_name!r}, "
            f"secret='***', issuer={self.issuer!r})"
        )


@dataclass(frozen=True, slots=True)
class AppConfig:
    """``config.json`` から読み込まれるアプリケーション設定を表すモデル。

    鍵やシークレットそのものではなく、鍵ファイルと暗号化データファイルの
    パスのみを保持する。
    """

    key_path: Path
    storage_path: Path


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedPayload:
    """暗号化されたTOTPシークレットデータファイルの構造を表すモデル。

    ``nonce`` と ``ciphertext`` はバイト列であり、そのまま文字列表現へ
    出力しないよう ``__repr__`` を独自定義する。
    """

    version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes

    def __repr__(self) -> str:
        """暗号文とnonceの生バイト列を含まない安全な文字列表現を返す。"""
        return (
            f"{self.__class__.__name__}(version={self.version!r}, "
            f"algorithm={self.algorithm!r}, "
            f"nonce=<{len(self.nonce)} bytes>, "
            f"ciphertext=<{len(self.ciphertext)} bytes>)"
        )
