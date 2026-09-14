"""totp_cli.core.secure_storage.SecureStorage の単体テスト。"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

import pytest

from totp_cli.core.secure_storage import SecureStorage
from totp_cli.domain.exceptions import InvalidKeyError, StorageCorruptedError
from totp_cli.domain.models import EncryptedPayload, SecretRecord


@pytest.fixture
def storage() -> SecureStorage:
    """テスト対象のSecureStorageインスタンスを返す。"""
    return SecureStorage()


@pytest.fixture
def key() -> bytes:
    """テスト用の32バイトAES-256鍵を返す。"""
    return os.urandom(32)


@pytest.fixture
def other_key() -> bytes:
    """元の鍵とは異なる32バイトAES-256鍵を返す。"""
    return os.urandom(32)


@pytest.fixture
def sample_records() -> dict[str, SecretRecord]:
    """テスト用の複数サービス分のSecretRecordを返す。"""
    return {
        "github": SecretRecord(
            service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
        ),
        "aws": SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None),
    }


def _write_encrypted_file(path: Path, encrypted: EncryptedPayload) -> None:
    """DESIGN.md記載のペイロード形式に厳密に従い、暗号化ファイルを直接書き出す補助関数。"""
    document = {
        "version": encrypted.version,
        "algorithm": encrypted.algorithm,
        "nonce": base64.b64encode(encrypted.nonce).decode("ascii"),
        "ciphertext": base64.b64encode(encrypted.ciphertext).decode("ascii"),
    }
    path.write_text(json.dumps(document), encoding="utf-8")


class TestEncryptDecryptRoundTrip:
    """encrypt / decrypt のラウンドトリップに関するテスト。"""

    def test_decrypt_recovers_original_plaintext(
        self, storage: SecureStorage, key: bytes
    ) -> None:
        """暗号化したデータを同じ鍵で復号すると元の平文が復元されることを確認する。"""
        plaintext = b'{"version": 1, "services": {}}'
        encrypted = storage.encrypt(plaintext, key)
        assert storage.decrypt(encrypted, key) == plaintext

    def test_encrypted_payload_has_expected_metadata(
        self, storage: SecureStorage, key: bytes
    ) -> None:
        """EncryptedPayloadのversion/algorithm/nonceサイズが仕様どおりであることを確認する。"""
        encrypted = storage.encrypt(b"payload", key)
        assert encrypted.version == 1
        assert encrypted.algorithm == "AES-256-GCM"
        assert len(encrypted.nonce) == 12

    def test_nonce_is_fresh_for_each_encryption(
        self, storage: SecureStorage, key: bytes
    ) -> None:
        """同じ平文・鍵でも呼び出しごとに異なるnonceが生成されることを確認する。"""
        first = storage.encrypt(b"same-payload", key)
        second = storage.encrypt(b"same-payload", key)
        assert first.nonce != second.nonce
        assert first.ciphertext != second.ciphertext

    def test_decrypt_with_wrong_key_raises_storage_corrupted_error(
        self, storage: SecureStorage, key: bytes, other_key: bytes
    ) -> None:
        """異なる鍵での復号が認証タグ検証失敗としてStorageCorruptedErrorになることを確認する。"""
        encrypted = storage.encrypt(b'{"version": 1, "services": {}}', key)
        with pytest.raises(StorageCorruptedError):
            storage.decrypt(encrypted, other_key)

    @pytest.mark.parametrize("invalid_key", [b"", b"short", b"\x00" * 16, b"\x00" * 33])
    def test_encrypt_rejects_invalid_key_size(
        self, storage: SecureStorage, invalid_key: bytes
    ) -> None:
        """32バイトでない鍵でのencryptがInvalidKeyErrorになることを確認する。"""
        with pytest.raises(InvalidKeyError):
            storage.encrypt(b"payload", invalid_key)

    @pytest.mark.parametrize("invalid_key", [b"", b"short", b"\x00" * 16, b"\x00" * 33])
    def test_decrypt_rejects_invalid_key_size(
        self, storage: SecureStorage, key: bytes, invalid_key: bytes
    ) -> None:
        """32バイトでない鍵でのdecryptがInvalidKeyErrorになることを確認する。"""
        encrypted = storage.encrypt(b"payload", key)
        with pytest.raises(InvalidKeyError):
            storage.decrypt(encrypted, invalid_key)

    def test_decrypt_rejects_unsupported_version(
        self, storage: SecureStorage, key: bytes
    ) -> None:
        """未対応のバージョンを持つEncryptedPayloadがStorageCorruptedErrorになることを確認する。"""
        encrypted = storage.encrypt(b"payload", key)
        tampered = EncryptedPayload(
            version=2,
            algorithm=encrypted.algorithm,
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
        )
        with pytest.raises(StorageCorruptedError):
            storage.decrypt(tampered, key)

    def test_decrypt_rejects_unsupported_algorithm(
        self, storage: SecureStorage, key: bytes
    ) -> None:
        """未対応のアルゴリズム識別子を持つEncryptedPayloadがStorageCorruptedErrorになることを確認する。"""
        encrypted = storage.encrypt(b"payload", key)
        tampered = EncryptedPayload(
            version=encrypted.version,
            algorithm="AES-128-GCM",
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
        )
        with pytest.raises(StorageCorruptedError):
            storage.decrypt(tampered, key)


class TestTamperDetection:
    """暗号化ファイルの改ざん検知に関するテスト。"""

    def test_flipped_ciphertext_byte_is_detected(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """ciphertextの1バイトを改ざんすると認証タグ検証に失敗しStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})

        document = json.loads(target.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_flipped_nonce_byte_is_detected(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """nonceの1バイトを改ざんすると認証タグ検証に失敗しStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})

        document = json.loads(target.read_text(encoding="utf-8"))
        nonce = bytearray(base64.b64decode(document["nonce"]))
        nonce[0] ^= 0xFF
        document["nonce"] = base64.b64encode(bytes(nonce)).decode("ascii")
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_does_not_retry_with_a_different_key_on_failure(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """認証タグ検証に失敗した場合、別の鍵での再試行を行わず例外を送出することを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        document = json.loads(target.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[-1] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)
        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, other_key)


class TestInvalidFileFormat:
    """暗号化ファイルの形式不正に関するテスト。"""

    def test_missing_file_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """ファイルが存在しない場合にStorageCorruptedErrorが送出されることを確認する。"""
        missing = tmp_path / "missing.enc"
        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(missing, key)

    def test_invalid_json_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """JSONとして解析できないファイルがStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        target.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_json_array_instead_of_object_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """JSONのトップレベルがオブジェクトでない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        target.write_text("[]", encoding="utf-8")
        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    @pytest.mark.parametrize(
        "missing_field", ["version", "algorithm", "nonce", "ciphertext"]
    )
    def test_missing_required_field_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes, missing_field: str
    ) -> None:
        """必須フィールドが欠落したファイルがStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        del document[missing_field]
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_invalid_base64_nonce_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """nonceが正しいBase64でない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        document["nonce"] = "not-valid-base64!!"
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_document_missing_services_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """復号後のJSONにservicesが無い場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        encrypted = storage.encrypt(b'{"version": 1}', key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_service_entry_missing_secret_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """復号後のサービスエントリにsecretが無い場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        plaintext = json.dumps(
            {"version": 1, "services": {"github": {"issuer": "GitHub"}}}
        ).encode("utf-8")
        encrypted = storage.encrypt(plaintext, key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_service_entry_not_an_object_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """サービスエントリがオブジェクトでない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        plaintext = json.dumps(
            {"version": 1, "services": {"github": "not-an-object"}}
        ).encode("utf-8")
        encrypted = storage.encrypt(plaintext, key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_service_entry_with_non_string_issuer_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """issuerが文字列でない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        plaintext = json.dumps(
            {
                "version": 1,
                "services": {"github": {"secret": "JBSWY3DPEHPK3PXP", "issuer": 123}},
            }
        ).encode("utf-8")
        encrypted = storage.encrypt(plaintext, key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_plaintext_not_valid_json_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """復号は成功してもJSONとして解析できない平文の場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        encrypted = storage.encrypt(b"this is not json at all", key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_plaintext_not_a_json_object_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """復号後の平文がJSONオブジェクトでない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        encrypted = storage.encrypt(b"[1, 2, 3]", key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_decrypted_plaintext_version_mismatch_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """復号後の平文JSONのversionが未対応の場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        plaintext = json.dumps({"version": 2, "services": {}}).encode("utf-8")
        encrypted = storage.encrypt(plaintext, key)
        _write_encrypted_file(target, encrypted)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    @pytest.mark.parametrize("field", ["version", "algorithm"])
    def test_raw_file_field_with_wrong_type_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes, field: str
    ) -> None:
        """暗号化ファイルのversion/algorithmが期待する型でない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        document[field] = ["wrong-type"]
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    @pytest.mark.parametrize("field", ["nonce", "ciphertext"])
    def test_raw_file_nonce_or_ciphertext_with_wrong_type_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes, field: str
    ) -> None:
        """暗号化ファイルのnonce/ciphertextが文字列でない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        document[field] = 12345
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)


class TestCryptoBoundaryValues:
    """nonce/ciphertextの境界値および大規模ペイロードに関するテスト。"""

    @pytest.mark.parametrize("nonce_length", [0, 4, 7, 11, 13, 16, 24])
    def test_nonce_with_length_other_than_12_bytes_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes, nonce_length: int
    ) -> None:
        """Base64デコード後のnonceが12バイトでない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        document["nonce"] = base64.b64encode(os.urandom(nonce_length)).decode("ascii")
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    @pytest.mark.parametrize("ciphertext_length", [0, 1, 8, 15])
    def test_ciphertext_shorter_than_auth_tag_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes, ciphertext_length: int
    ) -> None:
        """ciphertextが認証タグ長（16バイト）未満の場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        document["ciphertext"] = base64.b64encode(os.urandom(ciphertext_length)).decode(
            "ascii"
        )
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_large_payload_round_trip_with_1000_services(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """1,000件規模のサービスレコードでも保存・復号のラウンドトリップが正しく行われることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        records = {
            f"service-{index:04d}": SecretRecord(
                service_name=f"service-{index:04d}",
                secret=base64.b32encode(os.urandom(10)).decode("ascii").rstrip("="),
                issuer=f"Issuer{index:04d}" if index % 2 == 0 else None,
            )
            for index in range(1000)
        }

        storage.save_secrets(target, key, records)
        loaded = storage.load_secrets(target, key)

        assert len(loaded) == 1000
        assert loaded == records


class TestSaveAndLoadSecretsRoundTrip:
    """save_secrets / load_secrets のラウンドトリップに関するテスト。"""

    def test_round_trip_preserves_all_records(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """保存したサービス情報が読み込み後も完全に一致することを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        loaded = storage.load_secrets(target, key)
        assert loaded == sample_records

    def test_initialize_creates_empty_loadable_storage(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """initializeが空のサービス情報を持つ読み込み可能なファイルを作成することを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.initialize(target, key)
        assert storage.load_secrets(target, key) == {}

    def test_save_secrets_creates_parent_directories(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """保存先の親ディレクトリが存在しない場合でも自動作成されることを確認する。"""
        target = tmp_path / "nested" / "vault" / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        assert storage.load_secrets(target, key) == sample_records

    def test_file_on_disk_matches_documented_payload_format(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """保存されたファイルがDESIGN.md記載のペイロード形式に一致することを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})
        document = json.loads(target.read_text(encoding="utf-8"))
        assert document.keys() == {"version", "algorithm", "nonce", "ciphertext"}
        assert document["version"] == 1
        assert document["algorithm"] == "AES-256-GCM"
        base64.b64decode(document["nonce"], validate=True)
        base64.b64decode(document["ciphertext"], validate=True)


class TestInitializeErrorHandling:
    """initialize の異常系および生成ファイルのスキーマ厳密検証に関するテスト。"""

    @pytest.mark.parametrize(
        "invalid_key", [b"", b"short", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33]
    )
    def test_rejects_invalid_key_size_without_creating_file(
        self, storage: SecureStorage, tmp_path: Path, invalid_key: bytes
    ) -> None:
        """32バイトでない鍵の場合にInvalidKeyErrorが送出され、ファイルが作成されないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        with pytest.raises(InvalidKeyError):
            storage.initialize(target, invalid_key)
        assert not target.exists()
        assert list(tmp_path.iterdir()) == []

    def test_directory_creation_permission_error_leaves_no_partial_file(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """保存先ディレクトリの作成に失敗した場合、PermissionErrorが伝播しファイルが残らないことを確認する。"""
        target = tmp_path / "vault" / "totp-secrets.enc"

        def _raise_permission_error(
            self: Path, *args: object, **kwargs: object
        ) -> None:
            raise PermissionError("permission denied")

        monkeypatch.setattr(Path, "mkdir", _raise_permission_error)
        with pytest.raises(PermissionError):
            storage.initialize(target, key)

        assert not target.exists()
        assert not (tmp_path / "vault").exists()

    def test_write_permission_error_leaves_no_leftover_temp_file(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """一時ファイルの作成に失敗した場合、PermissionErrorが伝播し一時ファイルが残らないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"

        def _raise_permission_error(*args: object, **kwargs: object) -> tuple[int, str]:
            raise PermissionError("permission denied")

        monkeypatch.setattr(tempfile, "mkstemp", _raise_permission_error)
        with pytest.raises(PermissionError):
            storage.initialize(target, key)

        assert list(tmp_path.iterdir()) == []

    def test_created_file_matches_documented_schema_exactly(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """initialize直後のファイルがDESIGN.md記載のペイロードスキーマに厳密に一致することを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.initialize(target, key)

        document = json.loads(target.read_text(encoding="utf-8"))
        assert set(document.keys()) == {"version", "algorithm", "nonce", "ciphertext"}
        assert document["version"] == 1
        assert document["algorithm"] == "AES-256-GCM"
        assert isinstance(document["nonce"], str)
        assert isinstance(document["ciphertext"], str)
        assert len(base64.b64decode(document["nonce"], validate=True)) == 12

        encrypted = EncryptedPayload(
            version=document["version"],
            algorithm=document["algorithm"],
            nonce=base64.b64decode(document["nonce"]),
            ciphertext=base64.b64decode(document["ciphertext"]),
        )
        plaintext = storage.decrypt(encrypted, key)
        assert json.loads(plaintext) == {"version": 1, "services": {}}


class TestAtomicWriteBehavior:
    """save_secretsのatomic書き込みに関するテスト。"""

    def test_no_temp_file_remains_after_successful_save(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """保存成功後、一時ファイルがディレクトリに残らないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        assert list(tmp_path.iterdir()) == [target]

    def test_original_file_is_untouched_when_replace_fails(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """os.replaceが失敗した場合、既存の暗号化データファイルが破壊されないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", _raise_os_error)
        new_records = {
            "new-service": SecretRecord(service_name="new-service", secret="AAAA")
        }
        with pytest.raises(OSError):
            storage.save_secrets(target, key, new_records)

        assert target.read_bytes() == original_bytes
        assert storage.load_secrets(target, key) == sample_records

    def test_no_leftover_temp_file_when_write_fails_before_replace(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """一時ファイル書き込み中に失敗した場合でも一時ファイルが残らないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated fsync failure")

        monkeypatch.setattr(os, "fsync", _raise_os_error)
        with pytest.raises(OSError):
            storage.save_secrets(target, key, {})

        assert list(tmp_path.iterdir()) == []


class TestRekey:
    """rekey に関するテスト。"""

    def test_data_is_readable_with_new_key_after_rekey(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """rekey後、新鍵でサービス情報が正しく読み込めることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        storage.rekey(target, key, other_key)

        assert storage.load_secrets(target, other_key) == sample_records

    def test_old_key_can_no_longer_decrypt_after_rekey(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """rekey後は旧鍵での復号がStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        storage.rekey(target, key, other_key)

        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_rekey_does_not_create_backup_of_secret_data(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """暗号化済みシークレットデータには`.1`等のローテーション用バックアップを作成しないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        storage.rekey(target, key, other_key)

        assert list(tmp_path.iterdir()) == [target]

    def test_rekey_aborts_and_keeps_original_file_when_verification_fails(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """再暗号化後の検証に失敗した場合、既存の暗号化データファイルを変更せず一時ファイルも残さないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        def _fail_verification(*args: object, **kwargs: object) -> None:
            raise StorageCorruptedError("再暗号化データの検証に失敗しました")

        monkeypatch.setattr(storage, "_verify_prepared_rekey", _fail_verification)

        with pytest.raises(StorageCorruptedError):
            storage.rekey(target, key, other_key)

        assert target.read_bytes() == original_bytes
        assert list(tmp_path.iterdir()) == [target]
        assert storage.load_secrets(target, key) == sample_records

    def test_verify_prepared_rekey_raises_when_decrypted_records_mismatch(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """検証用に復号した内容が期待するサービス情報と一致しない場合にStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, other_key, sample_records)

        mismatched_expectation = {
            "different-service": SecretRecord(
                service_name="different-service", secret="ZZZZZZZZ"
            )
        }
        with pytest.raises(StorageCorruptedError):
            storage._verify_prepared_rekey(target, other_key, mismatched_expectation)

    @pytest.mark.parametrize(
        "invalid_key", [b"", b"short", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33]
    )
    def test_rejects_invalid_old_key_size_without_modifying_file(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
        invalid_key: bytes,
    ) -> None:
        """old_keyが32バイトでない場合にInvalidKeyErrorが送出され、既存ファイルが変更されないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        with pytest.raises(InvalidKeyError):
            storage.rekey(target, invalid_key, other_key)

        assert target.read_bytes() == original_bytes
        assert list(tmp_path.iterdir()) == [target]

    @pytest.mark.parametrize(
        "invalid_key", [b"", b"short", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33]
    )
    def test_rejects_invalid_new_key_size_without_modifying_file(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
        invalid_key: bytes,
    ) -> None:
        """new_keyが32バイトでない場合にInvalidKeyErrorが送出され、既存ファイルが変更されないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        with pytest.raises(InvalidKeyError):
            storage.rekey(target, key, invalid_key)

        assert target.read_bytes() == original_bytes
        assert list(tmp_path.iterdir()) == [target]

    def test_rekey_on_tampered_file_raises_storage_corrupted_error_and_leaves_file_untouched(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """改ざんされた暗号化ファイルへのrekeyがStorageCorruptedErrorになり、ファイルを変更しないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        document = json.loads(target.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        target.write_text(json.dumps(document), encoding="utf-8")
        tampered_bytes = target.read_bytes()

        with pytest.raises(StorageCorruptedError):
            storage.rekey(target, key, other_key)

        assert target.read_bytes() == tampered_bytes
        assert list(tmp_path.iterdir()) == [target]

    def test_rekey_on_missing_file_raises_storage_corrupted_error(
        self, storage: SecureStorage, tmp_path: Path, key: bytes, other_key: bytes
    ) -> None:
        """存在しない暗号化データファイルへのrekeyがStorageCorruptedErrorになることを確認する。"""
        target = tmp_path / "missing.enc"

        with pytest.raises(StorageCorruptedError):
            storage.rekey(target, key, other_key)

        assert not target.exists()
        assert list(tmp_path.iterdir()) == []

    def test_rekey_with_unmatching_32byte_old_key_raises_storage_corrupted_error(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """鍵長は正しいが復号できないold_keyを渡した場合、StorageCorruptedErrorになり既存ファイルが変更されないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        with pytest.raises(StorageCorruptedError):
            storage.rekey(target, other_key, key)

        assert target.read_bytes() == original_bytes
        assert list(tmp_path.iterdir()) == [target]
        assert storage.load_secrets(target, key) == sample_records

    def test_rekey_cleans_up_temp_file_when_replace_fails(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        other_key: bytes,
        sample_records: dict[str, SecretRecord],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """rekey中にos.replaceが失敗した場合、一時ファイルが残らず元データが保持されることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", _raise_os_error)

        with pytest.raises(OSError):
            storage.rekey(target, key, other_key)

        assert target.read_bytes() == original_bytes
        assert list(tmp_path.iterdir()) == [target]
        assert storage.load_secrets(target, key) == sample_records


class TestZeroLeakageRule:
    """Zero Leakage Rule（平文シークレット・鍵内容の非漏洩）に関するテスト。"""

    def test_tamper_error_message_does_not_leak_secret_values(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """改ざん検知の例外メッセージにシークレットの値が含まれないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        document = json.loads(target.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        target.write_text(json.dumps(document), encoding="utf-8")

        with pytest.raises(StorageCorruptedError) as excinfo:
            storage.load_secrets(target, key)

        message = str(excinfo.value)
        assert "JBSWY3DPEHPK3PXP" not in message
        assert "KRSXG5CTMVRXEZLU" not in message
        assert key.hex() not in message

    def test_invalid_format_error_message_does_not_leak_key_bytes(
        self, storage: SecureStorage, tmp_path: Path, key: bytes
    ) -> None:
        """不正フォーマット検知の例外メッセージに鍵バイト列が含まれないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        target.write_text("{not valid json", encoding="utf-8")

        with pytest.raises(StorageCorruptedError) as excinfo:
            storage.load_secrets(target, key)

        assert key.hex() not in str(excinfo.value)

    def test_loaded_records_repr_does_not_leak_secret(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """load_secretsで取得したSecretRecordの文字列表現がシークレットを含まないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)

        loaded = storage.load_secrets(target, key)
        for record in loaded.values():
            representation = repr(record)
            assert record.secret not in representation

    def test_encrypted_file_on_disk_does_not_contain_plaintext_secret(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
    ) -> None:
        """暗号化ファイルの内容に平文のシークレット文字列がそのまま含まれないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        raw_content = target.read_text(encoding="utf-8")
        assert "JBSWY3DPEHPK3PXP" not in raw_content
        assert "KRSXG5CTMVRXEZLU" not in raw_content


class TestFileIOErrorHandling:
    """load_secrets / save_secrets におけるファイルI/O異常系のハンドリングに関するテスト。"""

    def test_load_secrets_wraps_permission_error_as_storage_corrupted_error(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """読み込み時にPermissionErrorが発生した場合、StorageCorruptedErrorへ安全に変換されることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})

        def _raise_permission_error(self: Path, *args: object, **kwargs: object) -> str:
            raise PermissionError("permission denied")

        monkeypatch.setattr(Path, "read_text", _raise_permission_error)
        with pytest.raises(StorageCorruptedError) as excinfo:
            storage.load_secrets(target, key)
        assert key.hex() not in str(excinfo.value)

    def test_load_secrets_wraps_generic_os_error_as_storage_corrupted_error(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """読み込み時に一般的なOSErrorが発生した場合もStorageCorruptedErrorへ変換されることを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, {})

        def _raise_os_error(self: Path, *args: object, **kwargs: object) -> str:
            raise OSError("simulated disk error")

        monkeypatch.setattr(Path, "read_text", _raise_os_error)
        with pytest.raises(StorageCorruptedError):
            storage.load_secrets(target, key)

    def test_save_secrets_directory_creation_permission_error_propagates_safely(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """保存先ディレクトリ作成時のPermissionErrorが伝播し、ファイルが作成されないことを確認する。"""
        target = tmp_path / "vault" / "totp-secrets.enc"

        def _raise_permission_error(
            self: Path, *args: object, **kwargs: object
        ) -> None:
            raise PermissionError("permission denied")

        monkeypatch.setattr(Path, "mkdir", _raise_permission_error)
        with pytest.raises(PermissionError):
            storage.save_secrets(target, key, {})

        assert not target.exists()

    def test_save_secrets_write_permission_error_does_not_corrupt_existing_file(
        self,
        storage: SecureStorage,
        tmp_path: Path,
        key: bytes,
        sample_records: dict[str, SecretRecord],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """一時ファイル作成時にPermissionErrorが発生しても、既存ファイルが破壊されないことを確認する。"""
        target = tmp_path / "totp-secrets.enc"
        storage.save_secrets(target, key, sample_records)
        original_bytes = target.read_bytes()

        def _raise_permission_error(*args: object, **kwargs: object) -> tuple[int, str]:
            raise PermissionError("permission denied")

        monkeypatch.setattr(tempfile, "mkstemp", _raise_permission_error)
        new_records = {"x": SecretRecord(service_name="x", secret="AAAAAAAA")}
        with pytest.raises(PermissionError):
            storage.save_secrets(target, key, new_records)

        assert target.read_bytes() == original_bytes
        assert list(tmp_path.iterdir()) == [target]
