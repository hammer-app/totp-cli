"""totp_cli.domain パッケージ（例外階層・ドメインモデル）の単体テスト。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from totp_cli.domain import (
    AppConfig,
    CommandParseError,
    EncryptedPayload,
    InvalidKeyError,
    InvalidSecretError,
    KeyNotFoundError,
    SecretRecord,
    ServiceNotFoundError,
    StorageCorruptedError,
    TotpCliError,
)


class TestExceptionHierarchy:
    """例外クラス階層に関するテスト。"""

    @pytest.mark.parametrize(
        ("exception_type", "expected_exit_code"),
        [
            (KeyNotFoundError, 3),
            (InvalidKeyError, 3),
            (StorageCorruptedError, 4),
            (ServiceNotFoundError, 5),
            (InvalidSecretError, 6),
            (CommandParseError, 2),
        ],
    )
    def test_subclasses_inherit_from_base_and_expose_exit_code(
        self,
        exception_type: type[TotpCliError],
        expected_exit_code: int,
    ) -> None:
        """各専用例外がTotpCliErrorを継承し、規定の終了コードを持つことを確認する。"""
        assert issubclass(exception_type, TotpCliError)
        assert exception_type.exit_code == expected_exit_code

    def test_base_error_default_exit_code_is_general_error(self) -> None:
        """基底例外の既定終了コードが一般エラー(1)であることを確認する。"""
        assert TotpCliError.exit_code == 1

    def test_exception_message_is_preserved_and_is_exception_subclass(self) -> None:
        """例外メッセージが保持され、標準のExceptionを継承していることを確認する。"""
        error = KeyNotFoundError("key file was not found")
        assert isinstance(error, Exception)
        assert str(error) == "key file was not found"

    def test_exception_message_does_not_require_secret_content(self) -> None:
        """例外メッセージに秘密情報を含めなくても構築できることを確認する（Zero Leakage Rule）。"""
        error = InvalidSecretError("secret format is invalid")
        assert "JBSWY" not in str(error)


class TestSecretRecord:
    """SecretRecord ドメインモデルに関するテスト。"""

    def test_fields_are_stored_correctly(self) -> None:
        """コンストラクタに渡した値が各フィールドへ正しく格納されることを確認する。"""
        record = SecretRecord(
            service_name="github",
            secret="JBSWY3DPEHPK3PXP",
            issuer="GitHub",
        )
        assert record.service_name == "github"
        assert record.secret == "JBSWY3DPEHPK3PXP"
        assert record.issuer == "GitHub"

    def test_issuer_defaults_to_none(self) -> None:
        """issuerを省略した場合にNoneが既定値となることを確認する。"""
        record = SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")
        assert record.issuer is None

    def test_instance_is_immutable(self) -> None:
        """フィールドへの再代入がFrozenInstanceErrorを送出することを確認する。"""
        record = SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")
        with pytest.raises(FrozenInstanceError):
            record.secret = "other-secret"  # type: ignore[misc]

    def test_repr_does_not_leak_secret(self) -> None:
        """文字列表現にシークレットの生の値が含まれないことを確認する（Zero Leakage Rule）。"""
        record = SecretRecord(
            service_name="github",
            secret="JBSWY3DPEHPK3PXP",
            issuer="GitHub",
        )
        representation = repr(record)
        assert "JBSWY3DPEHPK3PXP" not in representation
        assert "github" in representation


class TestAppConfig:
    """AppConfig ドメインモデルに関するテスト。"""

    def test_fields_are_stored_as_path(self) -> None:
        """key_pathとstorage_pathがPathとして格納されることを確認する。"""
        config = AppConfig(
            key_path=Path("C:/keys/master.key"),
            storage_path=Path("C:/data/totp-secrets.enc"),
        )
        assert config.key_path == Path("C:/keys/master.key")
        assert config.storage_path == Path("C:/data/totp-secrets.enc")

    def test_instance_is_immutable(self) -> None:
        """フィールドへの再代入がFrozenInstanceErrorを送出することを確認する。"""
        config = AppConfig(
            key_path=Path("master.key"),
            storage_path=Path("totp-secrets.enc"),
        )
        with pytest.raises(FrozenInstanceError):
            config.key_path = Path("other.key")  # type: ignore[misc]

    def test_repr_contains_only_paths_no_secret_material(self) -> None:
        """AppConfigは鍵の内容を保持しないため、文字列表現にはパスのみが含まれることを確認する。"""
        config = AppConfig(
            key_path=Path("master.key"),
            storage_path=Path("totp-secrets.enc"),
        )
        representation = repr(config)
        assert "master.key" in representation
        assert "totp-secrets.enc" in representation


class TestEncryptedPayload:
    """EncryptedPayload ドメインモデルに関するテスト。"""

    def test_fields_are_stored_correctly(self) -> None:
        """version、algorithm、nonce、ciphertextが正しく格納されることを確認する。"""
        payload = EncryptedPayload(
            version=1,
            algorithm="AES-256-GCM",
            nonce=b"\x00" * 12,
            ciphertext=b"\x01" * 32,
        )
        assert payload.version == 1
        assert payload.algorithm == "AES-256-GCM"
        assert payload.nonce == b"\x00" * 12
        assert payload.ciphertext == b"\x01" * 32

    def test_instance_is_immutable(self) -> None:
        """フィールドへの再代入がFrozenInstanceErrorを送出することを確認する。"""
        payload = EncryptedPayload(
            version=1,
            algorithm="AES-256-GCM",
            nonce=b"\x00" * 12,
            ciphertext=b"\x01" * 32,
        )
        with pytest.raises(FrozenInstanceError):
            payload.ciphertext = b"\x02" * 32  # type: ignore[misc]

    def test_repr_does_not_leak_raw_nonce_or_ciphertext_bytes(self) -> None:
        """文字列表現に生のnonce・ciphertextバイト列が含まれないことを確認する。"""
        nonce = b"\x11" * 12
        ciphertext = b"\x22" * 48
        payload = EncryptedPayload(
            version=1,
            algorithm="AES-256-GCM",
            nonce=nonce,
            ciphertext=ciphertext,
        )
        representation = repr(payload)
        assert nonce.hex() not in representation
        assert ciphertext.hex() not in representation
        assert "12 bytes" in representation
        assert "48 bytes" in representation


class TestDomainPackageExports:
    """totp_cli.domain パッケージの公開インターフェースに関するテスト。"""

    def test_all_expected_symbols_are_exported(self) -> None:
        """__all__に定義された全シンボルがdomainパッケージ直下から参照できることを確認する。"""
        import totp_cli.domain as domain_package

        expected_symbols = {
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
        }
        assert expected_symbols == set(domain_package.__all__)
        for symbol in expected_symbols:
            assert hasattr(domain_package, symbol)
