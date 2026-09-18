"""TOTP（RFC 6238）/HOTP（RFC 4226）準拠のワンタイムパスワード生成ロジックを定義するモジュール。

DESIGN.md 8章「TotpGenerator」に基づき、Base32形式シークレットの正規化・
検証、指定時刻に対応するTOTPコードの生成、および現在の有効期間の残り
秒数の計算を提供する。シークレットの生値は、いかなる場合もログや
例外メッセージへ出力しない（Zero Leakage Rule）。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import time
from typing import Callable

from vtotp.domain.exceptions import InvalidSecretError
from vtotp.i18n.catalog import MsgKey

#: 正規化後のBase32シークレットとして許容される文字集合（RFC 4648、末尾の`=`パディングを含む）。
_BASE32_PATTERN = re.compile(r"^[A-Z2-7]+=*$")

#: サポートするHMACダイジェストアルゴリズム名とhashlibコンストラクタの対応表。
_SUPPORTED_DIGESTS: dict[str, Callable[[], "hashlib._Hash"]] = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

#: TOTPの既定の時間ステップ（秒）。
DEFAULT_TIME_STEP: int = 30

#: TOTPコードの既定の桁数。
DEFAULT_DIGITS: int = 6

#: 既定のHMACダイジェストアルゴリズム。
DEFAULT_DIGEST: str = "sha1"


def _normalize_secret(secret: str) -> str:
    """前後の空白除去・内部スペース除去・大文字化によりシークレットを正規化する。"""
    return secret.strip().replace(" ", "").upper()


def _pad_base32(normalized_secret: str) -> str:
    """Base32文字列が8の倍数長になるよう `=` でパディングする。"""
    padding_needed = (-len(normalized_secret)) % 8
    return normalized_secret + "=" * padding_needed


def _normalize_and_validate(secret: str) -> str:
    """シークレットを正規化し、Base32として妥当かを検証する（内部用）。

    前後の空白除去・内部スペース除去・大文字化・パディング補正を行った
    うえで、RFC 4648のBase32文字集合およびBase32デコード可否を検証する。
    不正な場合は :class:`InvalidSecretError` を送出する。シークレットの
    内容そのものは例外メッセージへ含めない（Zero Leakage Rule）。

    戻り値は、パディング補正済みの正規化後Base32文字列である。
    """
    normalized = _normalize_secret(secret)
    if not normalized:
        raise InvalidSecretError(MsgKey.SECRET_EMPTY)
    if not _BASE32_PATTERN.match(normalized):
        raise InvalidSecretError(MsgKey.SECRET_INVALID_FORMAT)
    padded = _pad_base32(normalized)
    try:
        base64.b32decode(padded, casefold=True)
    except binascii.Error as exc:
        raise InvalidSecretError(MsgKey.SECRET_INVALID_FORMAT) from exc
    return padded


def _decode_secret(secret: str) -> bytes:
    """シークレットを正規化・検証したうえでBase32デコードし、バイト列を返す（内部用）。"""
    padded = _normalize_and_validate(secret)
    return base64.b32decode(padded, casefold=True)


def validate_secret(secret: str) -> None:
    """Base32シークレットの形式を検証する。

    前後の空白除去・内部スペース除去・大文字化を行ったうえで、RFC 4648の
    Base32文字集合として妥当かを検証する。不正な場合は
    :class:`InvalidSecretError` を送出する。
    """
    _normalize_and_validate(secret)


def _resolve_digest(digest: str) -> Callable[[], "hashlib._Hash"]:
    """ダイジェストアルゴリズム名からhashlibのコンストラクタを解決する。"""
    try:
        return _SUPPORTED_DIGESTS[digest.strip().lower()]
    except KeyError as exc:
        raise ValueError(
            f"サポートされていないダイジェストアルゴリズムです: {digest!r}"
        ) from exc


def _hotp(key: bytes, counter: int, digits: int, digest: str) -> str:
    """RFC 4226に基づき、鍵とカウンタ値からHOTPコードを生成する（内部用）。"""
    if digits <= 0:
        raise ValueError("digitsは1以上である必要があります")
    if counter < 0:
        raise ValueError("counterは0以上である必要があります")

    digest_constructor = _resolve_digest(digest)
    counter_bytes = counter.to_bytes(8, byteorder="big", signed=False)
    mac = hmac.new(key, counter_bytes, digest_constructor).digest()

    offset = mac[-1] & 0x0F
    truncated_end = offset + 4
    truncated = mac[offset:truncated_end]
    code_int = int.from_bytes(truncated, byteorder="big") & 0x7FFFFFFF
    code = code_int % (10**digits)
    return str(code).zfill(digits)


def _counter_for_time(time_step: int, timestamp: float) -> int:
    """RFC 6238のカウンタ値T（time_stepあたりの経過回数）を計算する（内部用）。"""
    if time_step <= 0:
        raise ValueError("time_stepは1以上である必要があります")
    return int(timestamp // time_step)


def generate_totp(
    secret: str,
    time_step: int = DEFAULT_TIME_STEP,
    digits: int = DEFAULT_DIGITS,
    digest: str = DEFAULT_DIGEST,
    for_time: float | int | None = None,
) -> str:
    """指定時刻（省略時は現在時刻）に対応するTOTPコードを生成する。

    RFC 6238に基づき、Base32形式の `secret` を検証・デコードしたうえで
    HOTP（RFC 4226）のカウンタ値からコードを算出する。`secret` の
    前後の空白・内部スペース・大文字小文字の違いは吸収して正規化する。
    """
    key = _decode_secret(secret)
    timestamp = time.time() if for_time is None else float(for_time)
    counter = _counter_for_time(time_step, timestamp)
    return _hotp(key, counter, digits=digits, digest=digest)


def remaining_seconds(
    time_step: int = DEFAULT_TIME_STEP,
    for_time: float | int | None = None,
) -> int:
    """指定時刻（省略時は現在時刻）における、現在のTOTP有効期間の残り秒数を返す。"""
    if time_step <= 0:
        raise ValueError("time_stepは1以上である必要があります")
    timestamp = time.time() if for_time is None else float(for_time)
    counter = int(timestamp // time_step)
    next_boundary = (counter + 1) * time_step
    return int(next_boundary - timestamp)


class TotpGenerator:
    """TOTP/HOTPコード生成をオブジェクト指向のインターフェースで提供するクラス。

    既定の桁数・時間ステップ・ダイジェストアルゴリズムをインスタンスに
    保持し、実際の計算は本モジュールの関数群（:func:`generate_totp` 等）
    へ委譲する。
    """

    def __init__(
        self,
        digits: int = DEFAULT_DIGITS,
        time_step: int = DEFAULT_TIME_STEP,
        digest: str = DEFAULT_DIGEST,
    ) -> None:
        """既定の桁数・時間ステップ・ダイジェストアルゴリズムを設定する。"""
        self.digits = digits
        self.time_step = time_step
        self.digest = digest

    def validate_secret(self, secret: str) -> str:
        """Base32シークレットの形式を検証し、正規化済みの文字列を返す。

        不正な文字を含む場合やBase32として解釈できない場合は
        :class:`InvalidSecretError` を送出する。
        """
        return _normalize_and_validate(secret)

    def generate(self, secret: str, for_time: float | int | None = None) -> str:
        """現在時刻（または `for_time` 指定時刻）に対応するTOTPコードを生成する。"""
        return generate_totp(
            secret,
            time_step=self.time_step,
            digits=self.digits,
            digest=self.digest,
            for_time=for_time,
        )

    def remaining_seconds(self, for_time: float | int | None = None) -> int:
        """現在（または `for_time` 指定時刻）のTOTP有効期間の残り秒数を返す。"""
        return remaining_seconds(time_step=self.time_step, for_time=for_time)
