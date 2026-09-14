"""暗号化されたTOTPシークレットストレージの読み書きを担う SecureStorage を定義するモジュール。

DESIGN.md 7章「SecureStorage」に基づき、AES-256-GCMによる暗号化・復号、
JSON形式の暗号化ファイルの読み込み・保存・再暗号化（rekey）を提供する。
復号後の平文データ（TOTPシークレットを含むJSON）は、いかなる場合も
ログや例外メッセージへ出力しない（Zero Leakage Rule）。
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from totp_cli.domain.exceptions import InvalidKeyError, StorageCorruptedError
from totp_cli.domain.models import EncryptedPayload, SecretRecord


class SecureStorage:
    """暗号化済みTOTPシークレットストレージファイルの読み書きを行うクラス。

    暗号化ファイルはJSON形式で
    ``{"version": 1, "algorithm": "AES-256-GCM", "nonce": <base64>,
    "ciphertext": <base64>}`` の構造を持つ。復号された平文JSONはこのクラス
    のインスタンス変数として保持されず、処理スコープ内でのみ扱われる。
    """

    #: マスターキーの必須サイズ（AES-256のため32バイト）。
    KEY_SIZE_BYTES: int = 32

    #: 暗号化アルゴリズム識別子。
    ALGORITHM: str = "AES-256-GCM"

    #: 暗号化ファイルフォーマットのバージョン。
    FORMAT_VERSION: int = 1

    #: AES-256-GCMのnonceサイズ（12バイト）。
    NONCE_SIZE_BYTES: int = 12

    def initialize(self, path: Path, key: bytes) -> None:
        """空のサービスデータを暗号化して新規作成する。"""
        self.save_secrets(path, key, {})

    def load_secrets(self, path: Path, key: bytes) -> dict[str, SecretRecord]:
        """暗号化ファイルを復号してサービス情報を返す。

        フォーマット不正・改ざん（認証タグ検証失敗）・復号後データの
        構造不正のいずれの場合も :class:`StorageCorruptedError` を送出する。
        """
        encrypted_payload = self._read_encrypted_payload(path)
        plaintext = self.decrypt(encrypted_payload, key)
        document = self._parse_plaintext_document(plaintext)
        return self._records_from_document(document)

    def save_secrets(
        self,
        path: Path,
        key: bytes,
        records: dict[str, SecretRecord],
    ) -> None:
        """サービス情報を暗号化し、atomicに保存する。"""
        document = self._document_from_records(records)
        plaintext = json.dumps(document, ensure_ascii=False).encode("utf-8")
        encrypted_payload = self.encrypt(plaintext, key)
        self._atomic_write_payload(path, encrypted_payload)

    def rekey(self, path: Path, old_key: bytes, new_key: bytes) -> None:
        """既存の暗号化データを旧鍵で復号し、新鍵で再暗号化してatomicに置き換える。

        新鍵で再暗号化した内容を正式パスと同じディレクトリの一時ファイルへ
        書き込み、その内容を新鍵で正しく復号でき、元のサービス情報と一致
        することを検証したうえで正式パスへatomicに置換する。検証に失敗
        した場合、既存の暗号化データファイルは変更しない。
        """
        records = self.load_secrets(path, old_key)
        document = self._document_from_records(records)
        plaintext = json.dumps(document, ensure_ascii=False).encode("utf-8")
        encrypted_payload = self.encrypt(plaintext, new_key)

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._write_payload_to_temp_file(path, encrypted_payload)
        try:
            self._verify_prepared_rekey(tmp_path, new_key, records)
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def encrypt(self, payload: bytes, key: bytes) -> EncryptedPayload:
        """平文バイト列をAES-256-GCMで暗号化し、EncryptedPayloadとして返す。"""
        self._validate_key_size(key)
        nonce = os.urandom(self.NONCE_SIZE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, payload, None)
        return EncryptedPayload(
            version=self.FORMAT_VERSION,
            algorithm=self.ALGORITHM,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decrypt(self, encrypted_payload: EncryptedPayload, key: bytes) -> bytes:
        """EncryptedPayloadを復号し、平文バイト列を返す。

        認証タグ検証に失敗した場合は復号を中止し、破損データを空データ
        として扱ったり、別の鍵で再試行したりしない。
        """
        self._validate_key_size(key)
        if encrypted_payload.version != self.FORMAT_VERSION:
            raise StorageCorruptedError(
                f"サポートされていない暗号化フォーマットバージョンです: {encrypted_payload.version!r}"
            )
        if encrypted_payload.algorithm != self.ALGORITHM:
            raise StorageCorruptedError(
                f"サポートされていない暗号化アルゴリズムです: {encrypted_payload.algorithm!r}"
            )
        try:
            return AESGCM(key).decrypt(
                encrypted_payload.nonce, encrypted_payload.ciphertext, None
            )
        except (InvalidTag, ValueError) as exc:
            raise StorageCorruptedError(
                "暗号化データの認証タグ検証に失敗しました"
                "（データの改ざん、破損、または不正な鍵の可能性があります）"
            ) from exc

    # --- 内部ヘルパー ---

    def _validate_key_size(self, key: bytes) -> None:
        """鍵が32バイトであることを検証する。"""
        if len(key) != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(
                f"鍵のサイズが不正です（{self.KEY_SIZE_BYTES}バイトである必要があります）"
            )

    def _document_from_records(
        self, records: dict[str, SecretRecord]
    ) -> dict[str, Any]:
        """SecretRecordの辞書を、暗号化前の論理JSON構造へ変換する。"""
        return {
            "version": self.FORMAT_VERSION,
            "services": {
                name: {"secret": record.secret, "issuer": record.issuer}
                for name, record in records.items()
            },
        }

    def _records_from_document(
        self, document: dict[str, Any]
    ) -> dict[str, SecretRecord]:
        """復号後の論理JSON構造をSecretRecordの辞書へ変換する。"""
        services = document.get("services")
        if not isinstance(services, dict):
            raise StorageCorruptedError("復号したデータの構造が不正です")

        records: dict[str, SecretRecord] = {}
        for service_name, entry in services.items():
            if not isinstance(service_name, str) or not isinstance(entry, dict):
                raise StorageCorruptedError("復号したデータの構造が不正です")
            secret = entry.get("secret")
            issuer = entry.get("issuer")
            if not isinstance(secret, str):
                raise StorageCorruptedError("復号したデータの構造が不正です")
            if issuer is not None and not isinstance(issuer, str):
                raise StorageCorruptedError("復号したデータの構造が不正です")
            records[service_name] = SecretRecord(
                service_name=service_name, secret=secret, issuer=issuer
            )
        return records

    def _parse_plaintext_document(self, plaintext: bytes) -> dict[str, Any]:
        """復号済みの平文JSONをパースする。

        パース失敗時は、平文の内容を例外メッセージへ含めない
        （Zero Leakage Rule）。
        """
        try:
            document = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageCorruptedError("復号したデータの形式が不正です") from exc

        if (
            not isinstance(document, dict)
            or document.get("version") != self.FORMAT_VERSION
        ):
            raise StorageCorruptedError("復号したデータの形式が不正です")
        return document

    def _read_encrypted_payload(self, path: Path) -> EncryptedPayload:
        """暗号化ファイルを読み込み、EncryptedPayloadへ変換する。"""
        if not path.is_file():
            raise StorageCorruptedError(f"暗号化データファイルが見つかりません: {path}")

        try:
            raw_document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StorageCorruptedError(
                f"暗号化データファイルを読み込めません: {path}"
            ) from exc

        if not isinstance(raw_document, dict):
            raise StorageCorruptedError(f"暗号化データファイルの形式が不正です: {path}")

        try:
            version = raw_document["version"]
            algorithm = raw_document["algorithm"]
            nonce_b64 = raw_document["nonce"]
            ciphertext_b64 = raw_document["ciphertext"]
        except KeyError as exc:
            raise StorageCorruptedError(
                f"暗号化データファイルの形式が不正です: {path}"
            ) from exc

        if not isinstance(version, int) or not isinstance(algorithm, str):
            raise StorageCorruptedError(f"暗号化データファイルの形式が不正です: {path}")
        if not isinstance(nonce_b64, str) or not isinstance(ciphertext_b64, str):
            raise StorageCorruptedError(f"暗号化データファイルの形式が不正です: {path}")

        try:
            nonce = base64.b64decode(nonce_b64, validate=True)
            ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        except binascii.Error as exc:
            raise StorageCorruptedError(
                f"暗号化データファイルの形式が不正です: {path}"
            ) from exc

        return EncryptedPayload(
            version=version,
            algorithm=algorithm,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def _serialize_payload(self, payload: EncryptedPayload) -> dict[str, Any]:
        """EncryptedPayloadをファイル保存用のJSON互換辞書へ変換する。"""
        return {
            "version": payload.version,
            "algorithm": payload.algorithm,
            "nonce": base64.b64encode(payload.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(payload.ciphertext).decode("ascii"),
        }

    def _write_payload_to_temp_file(
        self, path: Path, payload: EncryptedPayload
    ) -> Path:
        """暗号化ペイロードを、正式パスと同じディレクトリの一時ファイルへ書き込む。

        書き込み途中のプロセス終了によって既存の暗号化データファイルが
        破壊されないよう、正式パスへはまだ触れない。
        """
        document = self._serialize_payload(payload)
        fd, tmp_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(document, tmp_file)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        return tmp_path

    def _atomic_write_payload(self, path: Path, payload: EncryptedPayload) -> None:
        """暗号化ペイロードをJSONへシリアライズし、atomicに正式パスへ書き込む。"""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._write_payload_to_temp_file(path, payload)
        try:
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def _verify_prepared_rekey(
        self,
        tmp_path: Path,
        new_key: bytes,
        expected_records: dict[str, SecretRecord],
    ) -> None:
        """再暗号化した一時ファイルが新鍵で正しく復号でき、内容が一致することを検証する。"""
        verified_records = self.load_secrets(tmp_path, new_key)
        if verified_records != expected_records:
            raise StorageCorruptedError("再暗号化データの検証に失敗しました")
