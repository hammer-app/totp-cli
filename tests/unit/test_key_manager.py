"""totp_cli.core.key_manager.KeyManager の単体テスト。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from totp_cli.core.key_manager import KeyManager
from totp_cli.domain.exceptions import InvalidKeyError, KeyNotFoundError

#: chmodによる読み取り権限剥奪がOSレベルで機能しない環境（主にWindows）を判定する。
IS_WINDOWS = sys.platform.startswith("win")


@pytest.fixture
def key_manager() -> KeyManager:
    """テスト対象のKeyManagerインスタンスを返す。"""
    return KeyManager()


class TestGenerateKey:
    """generate_key に関するテスト。"""

    def test_generated_key_is_32_bytes(self, key_manager: KeyManager) -> None:
        """生成された鍵がAES-256に必要な32バイトであることを確認する。"""
        key = key_manager.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_generated_keys_are_random(self, key_manager: KeyManager) -> None:
        """連続して生成した鍵が毎回異なる（暗号学的に安全な乱数である）ことを確認する。"""
        first_key = key_manager.generate_key()
        second_key = key_manager.generate_key()
        assert first_key != second_key


class TestCreateKeyFile:
    """create_key_file に関するテスト。"""

    def test_creates_file_with_generated_key_when_key_is_none(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """keyを省略した場合に新規生成された32バイト鍵がファイルへ書き込まれることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        assert target.is_file()
        assert len(target.read_bytes()) == 32

    def test_creates_file_with_given_key_bytes(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """指定したバイト列がそのままファイルへ書き込まれることを確認する。"""
        target = tmp_path / "master.key"
        explicit_key = bytes(range(32))
        key_manager.create_key_file(target, key=explicit_key)
        assert target.read_bytes() == explicit_key

    def test_creates_parent_directories_if_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """出力先ディレクトリが存在しない場合でも自動作成されることを確認する。"""
        target = tmp_path / "nested" / "vault" / "master.key"
        key_manager.create_key_file(target)
        assert target.is_file()

    def test_rejects_key_with_invalid_size(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """32バイトでない鍵を渡した場合にInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        with pytest.raises(InvalidKeyError):
            key_manager.create_key_file(target, key=b"too-short")
        assert not target.exists()

    def test_does_not_leave_temp_file_behind(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """atomic書き込み後に一時ファイルが残らないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        remaining_files = list(tmp_path.iterdir())
        assert remaining_files == [target]


class TestCheckExistingKey:
    """check_existing_key に関するテスト。"""

    def test_returns_true_when_file_exists(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """既存の鍵ファイルがある場合にTrueを返すことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        assert key_manager.check_existing_key(target) is True

    def test_returns_false_when_file_does_not_exist(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にFalseを返すことを確認する。"""
        target = tmp_path / "missing.key"
        assert key_manager.check_existing_key(target) is False

    def test_returns_false_when_path_is_a_directory(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """パスがディレクトリの場合にFalseを返すことを確認する。"""
        directory = tmp_path / "master.key"
        directory.mkdir()
        assert key_manager.check_existing_key(directory) is False


class TestValidateKeyFile:
    """validate_key_file に関するテスト。"""

    def test_passes_for_valid_32_byte_file(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """正しい32バイトの鍵ファイルでは例外が発生しないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        key_manager.validate_key_file(target)

    def test_raises_key_not_found_error_when_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        target = tmp_path / "missing.key"
        with pytest.raises(KeyNotFoundError):
            key_manager.validate_key_file(target)

    def test_raises_invalid_key_error_when_path_is_directory(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """パスが通常ファイルでない場合にInvalidKeyErrorが送出されることを確認する。"""
        directory = tmp_path / "master.key"
        directory.mkdir()
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(directory)

    def test_raises_invalid_key_error_when_size_is_wrong(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """ファイルサイズが32バイトでない場合にInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\x00" * 16)
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(target)

    @pytest.mark.parametrize("size", [0, 31, 33])
    def test_raises_invalid_key_error_at_size_boundaries(
        self, key_manager: KeyManager, tmp_path: Path, size: int
    ) -> None:
        """31バイト・33バイト・0バイト（空ファイル）の境界値でInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\x00" * size)
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(target)

    @pytest.mark.skipif(
        IS_WINDOWS, reason="Windowsではos.chmodによる読み取り権限の剥奪が保証されない"
    )
    def test_raises_invalid_key_error_when_not_readable_via_chmod(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """os.chmodで読み取り権限を剥奪した実ファイルに対してInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        os.chmod(target, 0o000)
        try:
            with pytest.raises(InvalidKeyError):
                key_manager.validate_key_file(target)
        finally:
            os.chmod(target, 0o600)

    def test_raises_invalid_key_error_when_os_access_denies_read(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.access(path, os.R_OK)がFalseを返す場合に

        InvalidKeyErrorが送出されることを確認する（プラットフォーム非依存）。
        """
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        monkeypatch.setattr(os, "access", lambda path, mode: False)
        with pytest.raises(InvalidKeyError):
            key_manager.validate_key_file(target)


class TestVerifyKeyFile:
    """verify_key_file に関するテスト。"""

    def test_passes_for_valid_key_file(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """正しい鍵ファイルに対しては例外が発生しないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)
        key_manager.verify_key_file(target)

    def test_raises_key_not_found_error_when_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        target = tmp_path / "missing.key"
        with pytest.raises(KeyNotFoundError):
            key_manager.verify_key_file(target)


class TestLoadKey:
    """load_key に関するテスト。"""

    def test_returns_exact_key_bytes(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """ファイルに書き込んだ鍵の内容がそのまま読み込まれることを確認する。"""
        target = tmp_path / "master.key"
        explicit_key = secrets_like_key()
        key_manager.create_key_file(target, key=explicit_key)
        assert key_manager.load_key(target) == explicit_key

    def test_raises_key_not_found_error_when_missing(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        target = tmp_path / "missing.key"
        with pytest.raises(KeyNotFoundError):
            key_manager.load_key(target)

    def test_raises_invalid_key_error_when_size_is_wrong(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """サイズ不正な鍵ファイルに対してInvalidKeyErrorが送出されることを確認する。"""
        target = tmp_path / "master.key"
        target.write_bytes(b"\xff" * 40)
        with pytest.raises(InvalidKeyError):
            key_manager.load_key(target)

    def test_error_message_does_not_leak_key_content(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """例外メッセージに鍵の内容（バイト列）が含まれないことを確認する（Zero Leakage Rule）。"""
        target = tmp_path / "master.key"
        marker = b"\xde\xad\xbe\xef" * 10
        target.write_bytes(marker)
        with pytest.raises(InvalidKeyError) as excinfo:
            key_manager.load_key(target)
        assert marker.hex() not in str(excinfo.value)
        assert "deadbeef" not in str(excinfo.value)

    def test_raises_invalid_key_error_when_read_raises_permission_error(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """検証を通過した後の実読み込みでPermissionErrorが発生した場合にInvalidKeyErrorへ変換されることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target)

        def _raise_permission_error(self: Path) -> bytes:
            raise PermissionError("permission denied")

        monkeypatch.setattr(Path, "read_bytes", _raise_permission_error)
        with pytest.raises(InvalidKeyError):
            key_manager.load_key(target)

    def test_raises_invalid_key_error_when_read_bytes_length_mismatches_stat(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """statによる事前検証を通過しても、実読み込み結果が32バイトでなければInvalidKeyErrorになることを確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target, key=b"\x00" * 32)

        monkeypatch.setattr(Path, "read_bytes", lambda self: b"\x00" * 16)
        with pytest.raises(InvalidKeyError):
            key_manager.load_key(target)


class TestResolveKeyPath:
    """resolve_key_path に関するテスト（優先順位: CLI > 環境変数 > config.json）。"""

    def test_cli_path_has_highest_priority(self, key_manager: KeyManager) -> None:
        """CLIパスが指定されている場合、他の指定より優先されることを確認する。"""
        result = key_manager.resolve_key_path(
            cli_path=Path("cli.key"),
            config_path=Path("config.key"),
            environment_path=Path("env.key"),
        )
        assert result == Path("cli.key")

    def test_environment_path_used_when_cli_path_missing(
        self, key_manager: KeyManager
    ) -> None:
        """CLI未指定時は環境変数のパスがconfig.jsonより優先されることを確認する。"""
        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=Path("config.key"),
            environment_path=Path("env.key"),
        )
        assert result == Path("env.key")

    def test_config_path_used_when_only_config_available(
        self, key_manager: KeyManager
    ) -> None:
        """CLI・環境変数ともに未指定の場合、config.jsonのパスが使われることを確認する。"""
        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=Path("config.key"),
            environment_path=None,
        )
        assert result == Path("config.key")

    def test_raises_key_not_found_error_when_all_unspecified(
        self, key_manager: KeyManager
    ) -> None:
        """いずれの指定も存在しない場合にKeyNotFoundErrorが送出されることを確認する。"""
        with pytest.raises(KeyNotFoundError):
            key_manager.resolve_key_path(
                cli_path=None, config_path=None, environment_path=None
            )


def _read_key_path_from_environment(
    variable_name: str = "TOTP_KEY_PATH",
) -> Path | None:
    """環境変数からのパス読み取りを模した補助関数。

    呼び出し元（本来はConfigManager等）が実際のOS環境変数を読み取り、
    空文字列は「未指定」として扱ったうえで `KeyManager.resolve_key_path`
    へ渡すことを想定した変換ロジックをテスト内で再現する。
    """
    raw_value = os.environ.get(variable_name)
    if not raw_value:
        return None
    return Path(raw_value)


class TestResolveKeyPathWithRealEnvironmentAndConfig:
    """実際のOS環境変数とconfig.jsonファイルを用いたresolve_key_pathの統合的な優先順位検証。"""

    def test_cli_option_overrides_real_environment_variable_and_config_file(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """実際にTOTP_KEY_PATHとconfig.jsonが設定されていても、--key相当の指定が最優先されることを確認する。"""
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")
        env_path = tmp_path / "env.key"
        monkeypatch.setenv("TOTP_KEY_PATH", str(env_path))

        cli_path = tmp_path / "cli.key"
        result = key_manager.resolve_key_path(
            cli_path=cli_path,
            config_path=config_path,
            environment_path=_read_key_path_from_environment(),
        )
        assert result == cli_path

    def test_real_environment_variable_overrides_config_file_when_cli_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--key未指定時は、実際に設定されたTOTP_KEY_PATHがconfig.jsonより優先されることを確認する。"""
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")
        env_path = tmp_path / "env.key"
        monkeypatch.setenv("TOTP_KEY_PATH", str(env_path))

        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=config_path,
            environment_path=_read_key_path_from_environment(),
        )
        assert result == env_path

    def test_falls_back_to_config_file_when_environment_variable_is_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TOTP_KEY_PATHが未設定の場合、config.jsonのkey_pathが使われることを確認する。"""
        monkeypatch.delenv("TOTP_KEY_PATH", raising=False)
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")

        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=config_path,
            environment_path=_read_key_path_from_environment(),
        )
        assert result == config_path

    def test_empty_string_environment_variable_is_treated_as_unset(
        self,
        key_manager: KeyManager,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TOTP_KEY_PATHが空文字列の場合は未指定として扱われ、config.jsonへフォールバックすることを確認する。"""
        monkeypatch.setenv("TOTP_KEY_PATH", "")
        config_path = tmp_path / "config.key"
        config_path.write_text("dummy")

        environment_path = _read_key_path_from_environment()
        assert environment_path is None

        result = key_manager.resolve_key_path(
            cli_path=None,
            config_path=config_path,
            environment_path=environment_path,
        )
        assert result == config_path

    def test_raises_key_not_found_error_when_environment_empty_and_config_absent(
        self,
        key_manager: KeyManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """TOTP_KEY_PATHが空文字列で、CLIもconfig.jsonも未指定の場合はKeyNotFoundErrorになることを確認する。"""
        monkeypatch.setenv("TOTP_KEY_PATH", "")
        with pytest.raises(KeyNotFoundError):
            key_manager.resolve_key_path(
                cli_path=None,
                config_path=None,
                environment_path=_read_key_path_from_environment(),
            )


class TestRotatedKeyPaths:
    """rotated_key_paths に関するテスト。"""

    def test_returns_default_three_generations(self, key_manager: KeyManager) -> None:
        """既定では`.1`から`.3`までの3世代分のパスを返すことを確認する。"""
        base = Path("/vault/master.key")
        result = key_manager.rotated_key_paths(base)
        assert result == [
            Path("/vault/master.key.1"),
            Path("/vault/master.key.2"),
            Path("/vault/master.key.3"),
        ]

    def test_respects_custom_max_generations(self, key_manager: KeyManager) -> None:
        """max_generationsを指定した場合、その世代数分のパスが返ることを確認する。"""
        base = Path("/vault/master.key")
        result = key_manager.rotated_key_paths(base, max_generations=1)
        assert result == [Path("/vault/master.key.1")]


class TestRotateKeyFile:
    """rotate_key_file に関するテスト。"""

    def test_new_key_is_written_to_path(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """繰り上げ後、新鍵がpathへ保存されることを確認する。"""
        target = tmp_path / "master.key"
        new_key = key_manager.generate_key()
        returned_path = key_manager.rotate_key_file(target, new_key)
        assert returned_path == target
        assert target.read_bytes() == new_key

    def test_does_not_create_generation_files_when_nothing_existed(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """既存の鍵ファイルが無い状態からのローテーションでは`.1`が作成されないことを確認する。"""
        target = tmp_path / "master.key"
        key_manager.rotate_key_file(target, key_manager.generate_key())
        assert not Path(f"{target}.1").exists()

    def test_existing_key_is_shifted_to_generation_one(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """既存鍵が`<key_path>.1`へ退避されることを確認する。"""
        target = tmp_path / "master.key"
        old_key = key_manager.generate_key()
        key_manager.create_key_file(target, key=old_key)

        new_key = key_manager.generate_key()
        key_manager.rotate_key_file(target, new_key)

        assert target.read_bytes() == new_key
        assert Path(f"{target}.1").read_bytes() == old_key

    def test_full_rotation_shifts_all_generations_and_discards_oldest(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """3世代すべて存在する状態からのローテーションで最古の世代が破棄されることを確認する。"""
        target = tmp_path / "master.key"
        key0 = b"\x00" * 32
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        key3 = b"\x03" * 32

        target.write_bytes(key0)
        Path(f"{target}.1").write_bytes(key1)
        Path(f"{target}.2").write_bytes(key2)
        Path(f"{target}.3").write_bytes(key3)

        new_key = b"\x99" * 32
        key_manager.rotate_key_file(target, new_key)

        assert target.read_bytes() == new_key
        assert Path(f"{target}.1").read_bytes() == key0
        assert Path(f"{target}.2").read_bytes() == key1
        assert Path(f"{target}.3").read_bytes() == key2

    def test_repeated_rotations_never_exceed_max_generations(
        self, key_manager: KeyManager, tmp_path: Path
    ) -> None:
        """max_generationsを超える世代が繰り返しのrekeyでも一切生成されないことを境界値として確認する。"""
        target = tmp_path / "master.key"
        key_manager.create_key_file(target, key=b"\x00" * 32)

        history: list[bytes] = [b"\x00" * 32]
        for generation in range(1, 6):
            new_key = bytes([generation]) * 32
            key_manager.rotate_key_file(target, new_key)
            history.append(new_key)

            # MAX_ROTATED_KEYS(=3)を超える世代のファイルは存在しない。
            assert not Path(f"{target}.{key_manager.MAX_ROTATED_KEYS + 1}").exists()

        # 直近の3世代（.1, .2, .3）だけが、投入順の新しい方から残っている。
        expected_generations = list(reversed(history[-4:-1]))
        for offset, expected_key in enumerate(expected_generations, start=1):
            assert Path(f"{target}.{offset}").read_bytes() == expected_key
        assert target.read_bytes() == history[-1]


class TestAtomicWriteInternals:
    """_atomic_write_bytes / _restrict_permissions の内部フォールバック挙動に関するテスト。"""

    def test_temp_file_is_removed_when_replace_fails(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.replaceが失敗した場合、一時ファイルが残らず例外がそのまま伝播することを確認する。"""
        target = tmp_path / "master.key"

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", _raise_os_error)

        with pytest.raises(OSError):
            key_manager.create_key_file(target, key=b"\x00" * 32)

        assert not target.exists()
        assert list(tmp_path.iterdir()) == []

    def test_permission_restriction_failure_is_silently_ignored(
        self, key_manager: KeyManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """os.chmodが失敗しても鍵ファイルの作成自体は成功することを確認する（Windows等での既定挙動）。"""
        target = tmp_path / "master.key"

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("chmod not supported on this platform")

        monkeypatch.setattr(os, "chmod", _raise_os_error)

        key = b"\x07" * 32
        key_manager.create_key_file(target, key=key)
        assert target.read_bytes() == key


def secrets_like_key() -> bytes:
    """テスト用に、生成鍵と同じ形式（32バイト）のダミー鍵バイト列を返す。"""
    return bytes(range(32))
