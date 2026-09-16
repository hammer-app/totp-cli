"""vtotp.cli.handler.CliHandler の単体テスト。"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
from pathlib import Path
from typing import Callable

import pytest

from vtotp.cli.handler import CliHandler, ENV_KEY_PATH_VARIABLE
from vtotp.core.key_manager import KeyManager
from vtotp.core.secure_storage import SecureStorage
from vtotp.domain.models import SecretRecord


def _make_input(responses: list[str]) -> Callable[[], str]:
    """テスト用に、あらかじめ用意した応答を順番に返す入力関数を生成する。"""
    iterator = iter(responses)

    def _input() -> str:
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError from None

    return _input


@pytest.fixture
def stdout() -> io.StringIO:
    """テスト対象へ注入する標準出力用ストリームを返す。"""
    return io.StringIO()


@pytest.fixture
def stderr() -> io.StringIO:
    """テスト対象へ注入する標準エラー出力用ストリームを返す。"""
    return io.StringIO()


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    """テスト用の一時config.jsonパスを返す（実際のホームディレクトリを使わない）。"""
    return tmp_path / "config.json"


@pytest.fixture
def handler_factory(
    stdout: io.StringIO, stderr: io.StringIO, config_path: Path
) -> Callable[..., CliHandler]:
    """注入済みストリーム・一時config.jsonを持つCliHandlerを生成するファクトリを返す。"""

    def _factory(responses: list[str] | None = None) -> CliHandler:
        return CliHandler(
            stdout=stdout,
            stderr=stderr,
            config_path=config_path,
            input_func=_make_input(responses or []),
        )

    return _factory


@pytest.fixture
def initialized_handler(
    handler_factory: Callable[..., CliHandler],
    tmp_path: Path,
    stdout: io.StringIO,
    stderr: io.StringIO,
) -> tuple[CliHandler, Path]:
    """initを実行済みの状態のCliHandlerと鍵パスを返す。"""
    key_path = tmp_path / "master.key"
    handler = handler_factory()
    exit_code = handler.run(["init", "--key", str(key_path)])
    assert exit_code == 0
    stdout.truncate(0)
    stdout.seek(0)
    stderr.truncate(0)
    stderr.seek(0)
    return handler, key_path


class TestNormalizeArgv:
    """normalize_argv（省略形フォールバック）に関するテスト。"""

    @pytest.fixture
    def handler(self, handler_factory: Callable[..., CliHandler]) -> CliHandler:
        return handler_factory()

    def test_empty_argv_becomes_help(self, handler: CliHandler) -> None:
        """空のargvが`--help`へ変換されることを確認する。"""
        assert handler.normalize_argv([]) == ["--help"]

    @pytest.mark.parametrize(
        "command",
        [
            "init",
            "generate",
            "get",
            "add",
            "remove",
            "rm",
            "list",
            "ls",
            "rekey",
            "config",
        ],
    )
    def test_reserved_commands_are_not_rewritten(
        self, handler: CliHandler, command: str
    ) -> None:
        """予約済みサブコマンドはそのまま変更されないことを確認する。"""
        assert handler.normalize_argv([command, "extra"]) == [command, "extra"]

    def test_dash_g_is_translated_to_generate(self, handler: CliHandler) -> None:
        """`-g`が`generate`へ変換されることを確認する。"""
        assert handler.normalize_argv(["-g", "github"]) == ["generate", "github"]

    @pytest.mark.parametrize("flag", ["-h", "--help", "--version"])
    def test_dash_prefixed_options_are_not_rewritten(
        self, handler: CliHandler, flag: str
    ) -> None:
        """`-h`/`--help`/`--version`はそのまま変更されないことを確認する。"""
        assert handler.normalize_argv([flag]) == [flag]

    def test_unrecognized_first_token_is_treated_as_service_name(
        self, handler: CliHandler
    ) -> None:
        """未予約の第一引数がgenerateへフォールバックされることを確認する。"""
        assert handler.normalize_argv(["github", "--key", "k"]) == [
            "generate",
            "github",
            "--key",
            "k",
        ]

    def test_service_named_init_requires_explicit_generate(
        self, handler: CliHandler
    ) -> None:
        """サービス名が予約語（例: init）と衝突する場合はフォールバックされないことを確認する。"""
        assert handler.normalize_argv(["init"]) == ["init"]
        assert handler.normalize_argv(["generate", "init"]) == ["generate", "init"]


class TestInitCommand:
    """`init` サブコマンドに関するテスト。"""

    def test_creates_key_and_storage_and_updates_config(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
    ) -> None:
        """鍵ファイル・暗号化ストレージが作成され、config.jsonにkey_pathが保存されることを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", str(key_path)])

        assert exit_code == 0
        assert key_path.is_file()
        assert len(key_path.read_bytes()) == 32

        saved_config = json.loads(config_path.read_text(encoding="utf-8"))
        assert saved_config["key_path"] == str(key_path)

        storage_path = config_path.parent / "vtotp-secrets.enc"
        assert storage_path.is_file()
        # 暗号化ストレージファイルがDESIGN.md記載のペイロード形式で作成されていることも確認する。
        storage_document = json.loads(storage_path.read_text(encoding="utf-8"))
        assert storage_document["version"] == 1
        assert storage_document["algorithm"] == "AES-256-GCM"

    def test_prompts_for_key_path_when_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """--key省略時に対話入力で出力先パスを取得することを確認する。"""
        key_path = tmp_path / "interactive.key"
        handler = handler_factory([str(key_path)])
        exit_code = handler.run(["init"])
        assert exit_code == 0
        assert key_path.is_file()

    def test_cancels_when_key_path_prompt_is_empty(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力で空欄が入力された場合、CancelledError相当の終了コード7になることを確認する。

        単なる空欄入力は既定どおりキャンセル扱いのみとなり、引用符関連の
        個別エラーメッセージは表示されないことも合わせて確認する。
        """
        handler = handler_factory([""])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "引用符" not in stderr.getvalue()
        assert "パスを空にする" not in stderr.getvalue()

    def test_prompts_for_key_path_quoted_empty_string_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力に空の引用符（`""`）が入力された場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(['""'])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "パスを空にすることはできません" in stderr.getvalue()

    def test_prompts_for_key_path_quoted_whitespace_only_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力が空白のみを引用符で囲んだ値（`'   '`）の場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(["'   '"])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "パスを空にすることはできません" in stderr.getvalue()

    def test_prompts_for_key_path_mismatched_quotes_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力の引用符が一致しない場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(["\"invalid'"])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "引用符が正しく閉じられていません" in stderr.getvalue()

    def test_prompts_for_key_path_unclosed_quote_is_cancelled_with_error(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """対話入力の引用符が閉じられていない場合、エラーを表示したうえでキャンセルされることを確認する。"""
        handler = handler_factory(['"unclosed'])
        exit_code = handler.run(["init"])
        assert exit_code == 7
        assert "引用符が正しく閉じられていません" in stderr.getvalue()

    def test_prompts_for_key_path_strips_surrounding_double_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """対話入力の鍵パスがダブルクォーテーションで囲まれていても除去されることを確認する。

        Windowsエクスプローラーの「パスのコピー」等で、パス全体が
        ダブルクォーテーションで囲まれたまま貼り付けられるケースを想定する。
        """
        key_path = tmp_path / "個人用 Vault" / "master.key"
        quoted_input = f'"{key_path}"'
        handler = handler_factory([quoted_input])
        exit_code = handler.run(["init"])
        assert exit_code == 0
        assert key_path.is_file()

    def test_prompts_for_key_path_strips_surrounding_single_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """対話入力の鍵パスがシングルクォーテーションで囲まれていても除去されることを確認する。"""
        key_path = tmp_path / "vault" / "master.key"
        quoted_input = f"'{key_path}'"
        handler = handler_factory([quoted_input])
        exit_code = handler.run(["init"])
        assert exit_code == 0
        assert key_path.is_file()

    def test_existing_key_with_both_confirmations_accepted_is_overwritten(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """既存鍵がある場合、二段階警告に両方同意すると上書きされることを確認する。"""
        key_path = tmp_path / "master.key"
        key_path.write_bytes(b"\x00" * 32)
        handler = handler_factory(["y", "y"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 0
        assert key_path.read_bytes() != b"\x00" * 32

    def test_existing_key_rejected_at_first_warning_is_cancelled(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """第1警告を拒否した場合、鍵ファイルが変更されずキャンセル終了コード7になることを確認する。"""
        key_path = tmp_path / "master.key"
        original_bytes = b"\x00" * 32
        key_path.write_bytes(original_bytes)
        handler = handler_factory(["n"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 7
        assert key_path.read_bytes() == original_bytes

    def test_existing_key_rejected_at_second_warning_is_cancelled(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """第2警告を拒否した場合、鍵ファイルが変更されずキャンセル終了コード7になることを確認する。"""
        key_path = tmp_path / "master.key"
        original_bytes = b"\x00" * 32
        key_path.write_bytes(original_bytes)
        handler = handler_factory(["y", "n"])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 7
        assert key_path.read_bytes() == original_bytes

    def test_init_messages_do_not_leak_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stderr: io.StringIO,
    ) -> None:
        """initの案内メッセージに鍵の内容が含まれないことを確認する（Zero Leakage Rule）。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        handler.run(["init", "--key", str(key_path)])
        key_bytes = key_path.read_bytes()
        assert key_bytes.hex() not in stderr.getvalue()

    def test_key_option_strips_surrounding_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """`--key`にダブルクォーテーションで囲まれたパスを渡しても正しく解決されることを確認する。

        シェルの挙動によっては、引用符がargvの値そのものに残ったまま
        Pythonプロセスへ渡される場合があるため、argparseの`type`変換で
        正規化されることを検証する。
        """
        key_path = tmp_path / "個人用 Vault" / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", f'"{key_path}"'])
        assert exit_code == 0
        assert key_path.is_file()

    def test_short_key_option_strips_surrounding_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """短縮形`-k`にダブルクォーテーションで囲まれたパスを渡しても正しく解決されることを確認する。

        `--key`だけでなく短縮形`-k`でも同じ`type`変換（クォート除去）が
        適用されることを検証する。
        """
        key_path = tmp_path / "個人用 Vault" / "master.key"
        quoted_key_path = f'"{key_path}"'
        handler = handler_factory()
        exit_code = handler.run(["init", "-k", quoted_key_path])
        assert exit_code == 0

        # クォート除去後の期待パスに鍵ファイルが作成されていることを確認する。
        assert key_path.is_file()
        # クォート文字を含んだままのパスにはファイルが作成されていないことを確認する。
        assert not Path(quoted_key_path).exists()

        # `-k`で作成した鍵を、同じく`-k`＋クォート付きパスで読み込めることも確認する。
        add_handler = handler_factory()
        exit_code = add_handler.run(
            ["add", "github", "-k", quoted_key_path, "--secret", "JBSWY3DPEHPK3PXP"]
        )
        assert exit_code == 0

    def test_storage_option_strips_surrounding_quotes(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """`--storage`にクォート付きパスを渡しても正しく解決されることを確認する。

        クォート除去後の期待パスにのみファイルが作成され、クォート文字を
        含んだままのパスにはファイルが作成されないこと、また`list`実行時にも
        同様にクォートが除去され登録済みサービスが読み出せることまで検証する。
        """
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "-k", str(key_path)])
        assert exit_code == 0

        custom_storage = tmp_path / "custom" / "secrets.enc"
        quoted_storage = f'"{custom_storage}"'

        # addの時点で暗号化ストレージが存在している必要があるため、
        # カスタムパスへ事前に空のストレージを直接初期化しておく
        # （`init`は`--storage`を受け付けないため）。
        SecureStorage().initialize(custom_storage, key_path.read_bytes())

        add_handler = handler_factory()
        exit_code = add_handler.run(
            [
                "add",
                "github",
                "-k",
                str(key_path),
                "--storage",
                quoted_storage,
                "--secret",
                "JBSWY3DPEHPK3PXP",
            ]
        )
        assert exit_code == 0

        # クォート除去後の期待パスに暗号化ストレージが存在することを確認する。
        assert custom_storage.is_file()
        # クォート文字を含んだままのパスにはファイルが作成されていないことを確認する。
        assert not Path(quoted_storage).exists()

        list_handler = handler_factory()
        exit_code = list_handler.run(
            ["list", "-k", str(key_path), "--storage", quoted_storage]
        )
        assert exit_code == 0
        assert "github" in stdout.getvalue()

    @pytest.mark.parametrize(
        ("command", "option", "value"),
        [
            ("init", "--key", ""),
            ("init", "--key", '""'),
            ("init", "--key", "''"),
            ("list", "--storage", '"   "'),
            ("list", "--storage", "'   '"),
        ],
    )
    def test_key_or_storage_option_empty_after_normalization_returns_exit_code_2(
        self,
        handler_factory: Callable[..., CliHandler],
        stderr: io.StringIO,
        command: str,
        option: str,
        value: str,
    ) -> None:
        """引用符・空白除去後に空文字列となるパスを渡すと終了コード2になることを確認する。

        `--key`は`init`で、`--storage`は（`init`が受け付けないため）`list`で
        それぞれ検証し、対象オプション自体のパス検証が働くことを確認する。
        """
        handler = handler_factory()
        exit_code = handler.run([command, option, value])
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()
        assert "パスを空にすることはできません" in stderr.getvalue()

    @pytest.mark.parametrize(
        ("option", "value"),
        [
            ("--key", "\"invalid'"),
            ("--key", "'invalid\""),
            ("--key", '"unclosed'),
            ("--key", "unclosed'"),
        ],
    )
    def test_key_option_mismatched_or_unclosed_quotes_returns_exit_code_2(
        self,
        handler_factory: Callable[..., CliHandler],
        stderr: io.StringIO,
        option: str,
        value: str,
    ) -> None:
        """引用符が一致しない、または閉じられていないパスを渡すと終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["init", option, value])
        assert exit_code == 2
        assert "Traceback" not in stderr.getvalue()

    def test_argument_type_error_message_is_written_to_injected_stderr(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """不正なパス引数のエラーメッセージが注入済みのstderrへ書き込まれることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["init", "--key", '""'])
        assert exit_code == 2
        assert "パスを空にすることはできません" in stderr.getvalue()

    def test_invalid_windows_path_characters_return_exit_code_1_without_crashing(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """Windowsで不正な文字を含むパスを指定した場合、トレースバックを出さず終了コード1になることを確認する。"""
        if not sys.platform.startswith("win"):
            pytest.skip(
                "Windows固有の不正パス文字のテストのため、Windows以外ではスキップする"
            )

        invalid_key_path = tmp_path / "in?valid" / "master.key"
        handler = handler_factory()

        exit_code = handler.run(["init", "--key", str(invalid_key_path)])

        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert "エラー" in stderr.getvalue()
        # 未処理のPythonトレースバック（"Traceback (most recent call last)"）が
        # stderrへ現れていないことを確認する。
        assert "Traceback" not in stderr.getvalue()

    def test_os_error_during_key_creation_is_handled_gracefully(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        stderr: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """鍵ファイル作成時にOSErrorが発生した場合でも、run()がクラッシュせず
        終了コード1とわかりやすいエラーメッセージを返すことを確認する
        （プラットフォームに依存しない決定的な検証）。
        """

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated invalid path syntax")

        monkeypatch.setattr(Path, "mkdir", _raise_os_error)

        key_path = tmp_path / "vault" / "master.key"
        handler = handler_factory()

        exit_code = handler.run(["init", "--key", str(key_path)])

        assert exit_code == 1
        assert stdout.getvalue() == ""
        assert "エラー" in stderr.getvalue()
        assert "Traceback" not in stderr.getvalue()


class TestGenerateCommand:
    """`generate`/`get`/`-g`/省略形フォールバックに関するテスト。"""

    def _add_github(
        self, handler_factory: Callable[..., CliHandler], key_path: Path
    ) -> None:
        handler = handler_factory()
        exit_code = handler.run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--secret",
                "JBSWY3DPEHPK3PXP",
                "--issuer",
                "GitHub",
            ]
        )
        assert exit_code == 0

    def test_generate_outputs_six_digit_code_on_stdout(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """generateがstdoutへ6桁のコードのみを出力することを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["generate", "github", "--key", str(key_path)])
        assert exit_code == 0
        output = stdout.getvalue().strip()
        assert output.isdigit()
        assert len(output) == 6

    def test_get_alias_produces_same_code_as_generate(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`get`エイリアスが`generate`と同じ結果になることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["get", "github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_dash_g_alias_produces_a_code(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`-g`エイリアスが正しくgenerateとして動作することを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["-g", "github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_bare_service_name_falls_back_to_generate(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """予約語でないサービス名のみの指定が自動的にgenerateとして扱われることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["github", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_writes_remaining_seconds_bar_to_stderr(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stderr: io.StringIO,
    ) -> None:
        """remaining_secondsバーがstderrへ出力されることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])
        assert "[" in stderr.getvalue()
        assert "]" in stderr.getvalue()

    def test_stdout_contains_only_the_code_and_no_progress_bar(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """stdoutにはコードのみが出力され、remaining_secondsバーが含まれないことを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])

        output = stdout.getvalue()
        assert output == output.strip() + "\n"
        assert "[" not in output
        assert "]" not in output
        assert "#" not in output
        assert "-" not in output

    def test_stderr_does_not_contain_the_generated_code(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """stderrには生成された6桁コードが含まれないことを確認する（stdout/stderrの厳密な分離）。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])

        code = stdout.getvalue().strip()
        assert code not in stderr.getvalue()

    def test_missing_key_file_returns_exit_code_3(
        self, handler_factory: Callable[..., CliHandler], tmp_path: Path
    ) -> None:
        """鍵ファイルが存在しない場合、終了コード3になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(
            ["generate", "github", "--key", str(tmp_path / "missing.key")]
        )
        assert exit_code == 3

    def test_missing_service_returns_exit_code_5(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """未登録のサービスを指定した場合、終了コード5になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(["generate", "unknown-service", "--key", str(key_path)])
        assert exit_code == 5

    def test_corrupted_storage_returns_exit_code_4(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        config_path: Path,
    ) -> None:
        """暗号化ストレージが破損している場合、終了コード4になることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        config = json.loads(config_path.read_text(encoding="utf-8"))
        storage_path = config_path.parent / "vtotp-secrets.enc"
        document = json.loads(storage_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        storage_path.write_text(json.dumps(document), encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(["generate", "github", "--key", str(key_path)])
        assert exit_code == 4
        assert config  # サニティチェック（未使用警告防止）

    def test_generate_stdout_never_contains_secret_or_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """stdout/stderrのいずれにも元のシークレットや鍵の内容が現れないことを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)
        key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["generate", "github", "--key", str(key_path)])

        combined = stdout.getvalue() + stderr.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in combined
        assert key_bytes.hex() not in combined


class TestAddCommand:
    """`add` サブコマンドに関するテスト。"""

    def test_add_with_secret_flag_registers_service(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """--secretで指定したシークレットでサービスが登録されることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )
        assert exit_code == 0

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])

    def test_add_prompts_for_secret_when_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """--secret省略時に対話入力でシークレットを取得することを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory(["JBSWY3DPEHPK3PXP"])
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 0

    def test_add_cancelled_when_secret_prompt_is_empty(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """シークレット入力が空欄の場合、終了コード7（キャンセル）になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory([""])
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 7

    def test_add_with_invalid_secret_returns_exit_code_6(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """不正な形式のシークレットの場合、終了コード6になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "not-valid-base32!!!"]
        )
        assert exit_code == 6

    def test_add_duplicate_service_returns_exit_code_1(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """重複登録の場合、終了コード1（一般エラー）になることを確認する。"""
        _, key_path = initialized_handler
        first = handler_factory()
        assert (
            first.run(
                [
                    "add",
                    "github",
                    "--key",
                    str(key_path),
                    "--secret",
                    "JBSWY3DPEHPK3PXP",
                ]
            )
            == 0
        )

        second = handler_factory()
        exit_code = second.run(
            ["add", "github", "--key", str(key_path), "--secret", "KRSXG5CTMVRXEZLU"]
        )
        assert exit_code == 1

    def test_add_output_never_leaks_the_secret_value(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """addの標準出力・標準エラー出力に、渡したシークレットの値が含まれないことを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )
        combined = stdout.getvalue() + stderr.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in combined

    def test_duplicate_service_error_does_not_leak_the_attempted_secret(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """重複登録（終了コード1）の際、入力したシークレットがstdout/stderrに現れないことを確認する。"""
        _, key_path = initialized_handler
        first = handler_factory()
        assert (
            first.run(
                [
                    "add",
                    "github",
                    "--key",
                    str(key_path),
                    "--secret",
                    "JBSWY3DPEHPK3PXP",
                ]
            )
            == 0
        )
        stdout.truncate(0)
        stdout.seek(0)
        stderr.truncate(0)
        stderr.seek(0)

        second = handler_factory()
        exit_code = second.run(
            ["add", "github", "--key", str(key_path), "--secret", "KRSXG5CTMVRXEZLU"]
        )
        assert exit_code == 1

        combined = stdout.getvalue() + stderr.getvalue()
        assert "KRSXG5CTMVRXEZLU" not in combined
        assert "JBSWY3DPEHPK3PXP" not in combined

    def test_invalid_secret_error_does_not_leak_the_attempted_secret(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """不正なシークレット（終了コード6）の際、入力したシークレットがstdout/stderrに現れないことを確認する。"""
        _, key_path = initialized_handler
        invalid_secret = "not-valid-base32!!!"

        handler = handler_factory()
        exit_code = handler.run(
            ["add", "github", "--key", str(key_path), "--secret", invalid_secret]
        )
        assert exit_code == 6

        combined = stdout.getvalue() + stderr.getvalue()
        assert invalid_secret not in combined


class TestListCommand:
    """`list`/`ls` サブコマンドに関するテスト。"""

    def test_empty_registry_produces_empty_stdout(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """未登録の状態では標準出力が空であることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(["list", "--key", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue() == ""

    def test_lists_registered_services_without_secrets(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """登録済みサービス名が一覧に含まれ、シークレットは含まれないことを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory()
        add_handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )

        list_handler = handler_factory()
        exit_code = list_handler.run(["list", "--key", str(key_path)])
        assert exit_code == 0
        assert "github" in stdout.getvalue()
        assert "JBSWY3DPEHPK3PXP" not in stdout.getvalue()

    def test_ls_alias_behaves_like_list(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`ls`エイリアスが`list`と同じ結果になることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory()
        add_handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )

        ls_handler = handler_factory()
        exit_code = ls_handler.run(["ls", "--key", str(key_path)])
        assert exit_code == 0
        assert "github" in stdout.getvalue()


class TestRemoveCommand:
    """`remove`/`rm` サブコマンドに関するテスト。"""

    def _add_github(
        self, handler_factory: Callable[..., CliHandler], key_path: Path
    ) -> None:
        handler = handler_factory()
        handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )

    def test_remove_with_force_skips_confirmation(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """--force指定時は確認なしで削除されることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["remove", "github", "--force", "--key", str(key_path)])
        assert exit_code == 0

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])
        assert "github" not in stdout.getvalue()

    def test_remove_confirmed_deletes_service(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """確認に同意した場合、サービスが削除されることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory(["y"])
        exit_code = handler.run(["remove", "github", "--key", str(key_path)])
        assert exit_code == 0

    def test_remove_rejected_is_cancelled_and_keeps_service(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """確認を拒否した場合、キャンセルされサービスが残ることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory(["n"])
        exit_code = handler.run(["remove", "github", "--key", str(key_path)])
        assert exit_code == 7

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])
        assert "github" in stdout.getvalue()

    def test_remove_missing_service_returns_exit_code_5(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """未登録のサービスを削除しようとすると終了コード5になることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(
            ["remove", "unknown-service", "--force", "--key", str(key_path)]
        )
        assert exit_code == 5

    def test_rm_alias_behaves_like_remove(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`rm`エイリアスが`remove`と同じ結果になることを確認する。"""
        _, key_path = initialized_handler
        self._add_github(handler_factory, key_path)

        handler = handler_factory()
        exit_code = handler.run(["rm", "github", "--force", "--key", str(key_path)])
        assert exit_code == 0


class TestRekeyCommand:
    """`rekey` サブコマンドに関するテスト。"""

    def test_rekey_replaces_key_and_reencrypts_data(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """rekey後、新しい鍵でサービス情報が読み込めることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory()
        add_handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )
        old_key_bytes = key_path.read_bytes()

        rekey_handler = handler_factory()
        exit_code = rekey_handler.run(["rekey", "--key", str(key_path)])
        assert exit_code == 0
        assert key_path.read_bytes() != old_key_bytes

        list_handler = handler_factory()
        list_stdout_exit_code = list_handler.run(["list", "--key", str(key_path)])
        assert list_stdout_exit_code == 0

    def test_rekey_creates_generation_one_backup_of_old_key(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """rekey後、旧鍵が`<key_path>.1`へ退避されることを確認する。"""
        _, key_path = initialized_handler
        old_key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["rekey", "--key", str(key_path)])

        rotated = Path(f"{key_path}.1")
        assert rotated.is_file()
        assert rotated.read_bytes() == old_key_bytes

    def test_rekey_prompts_rotation_limit_warning_when_three_generations_exist(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`.3`世代が既に存在する場合、上限警告に同意しなければキャンセルされることを確認する。"""
        _, key_path = initialized_handler
        for generation in (1, 2, 3):
            Path(f"{key_path}.{generation}").write_bytes(bytes([generation]) * 32)

        handler = handler_factory(["n"])
        exit_code = handler.run(["rekey", "--key", str(key_path)])
        assert exit_code == 7

        accepted_handler = handler_factory(["y"])
        exit_code = accepted_handler.run(["rekey", "--key", str(key_path)])
        assert exit_code == 0

    def test_rekey_output_does_not_leak_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> None:
        """rekeyの出力に鍵の内容が含まれないことを確認する（Zero Leakage Rule）。"""
        _, key_path = initialized_handler
        old_key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["rekey", "--key", str(key_path)])
        new_key_bytes = key_path.read_bytes()

        combined = stdout.getvalue() + stderr.getvalue()
        assert old_key_bytes.hex() not in combined
        assert new_key_bytes.hex() not in combined


class TestShortKeyOption:
    """`-k`（`--key`の短縮オプション）が全サブコマンドで使用できることに関するテスト。"""

    def test_init_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """`init -k PATH`が`--key`指定時と同様に鍵ファイルを作成することを確認する。"""
        key_path = tmp_path / "master.key"
        handler = handler_factory()
        exit_code = handler.run(["init", "-k", str(key_path)])
        assert exit_code == 0
        assert key_path.is_file()

    def test_generate_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`generate -k PATH SERVICE`が正しく鍵パスを解決してコードを生成することを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory()
        add_handler.run(
            ["add", "github", "-k", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )

        handler = handler_factory()
        exit_code = handler.run(["generate", "github", "-k", str(key_path)])
        assert exit_code == 0
        assert stdout.getvalue().strip().isdigit()

    def test_add_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`add -k PATH SERVICE`が正しく鍵パスを解決してサービスを登録できることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(
            ["add", "github", "-k", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )
        assert exit_code == 0

    def test_list_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """`list -k PATH`が正しく鍵パスを解決してサービス一覧を表示できることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory()
        add_handler.run(
            ["add", "github", "-k", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )

        handler = handler_factory()
        exit_code = handler.run(["list", "-k", str(key_path)])
        assert exit_code == 0
        assert "github" in stdout.getvalue()

    def test_remove_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`remove -k PATH SERVICE`が正しく鍵パスを解決してサービスを削除できることを確認する。"""
        _, key_path = initialized_handler
        add_handler = handler_factory()
        add_handler.run(
            ["add", "github", "-k", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )

        handler = handler_factory()
        exit_code = handler.run(["remove", "github", "--force", "-k", str(key_path)])
        assert exit_code == 0

    def test_rekey_accepts_short_key_option(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """`rekey -k PATH`が正しく鍵パスを解決して鍵を更新できることを確認する。"""
        _, key_path = initialized_handler
        old_key_bytes = key_path.read_bytes()

        handler = handler_factory()
        exit_code = handler.run(["rekey", "-k", str(key_path)])
        assert exit_code == 0
        assert key_path.read_bytes() != old_key_bytes


class TestConfigCommand:
    """`config` サブコマンドに関するテスト。"""

    def test_shows_unset_key_path_before_init(
        self,
        handler_factory: Callable[..., CliHandler],
        stdout: io.StringIO,
    ) -> None:
        """init前はkey_pathが未設定として表示されることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "未設定" in stdout.getvalue()

    def test_shows_resolved_paths_after_init(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """init後は解決済みのkey_path/storage_pathが表示されることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert str(key_path) in stdout.getvalue()

    def test_config_output_does_not_leak_key_bytes(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        stdout: io.StringIO,
    ) -> None:
        """configコマンドの出力に鍵の内容が含まれないことを確認する。"""
        _, key_path = initialized_handler
        key_bytes = key_path.read_bytes()

        handler = handler_factory()
        handler.run(["config"])
        assert key_bytes.hex() not in stdout.getvalue()


class TestArgumentParseErrors:
    """CLI引数解析エラーに関するテスト。"""

    def test_missing_required_positional_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """generateにサービス名を指定しない場合、終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["generate"])
        assert exit_code == 2

    def test_unknown_option_returns_exit_code_2(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """未知のオプションを指定した場合、終了コード2になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["list", "--no-such-option"])
        assert exit_code == 2

    def test_parse_error_message_is_written_to_injected_stderr(
        self, handler_factory: Callable[..., CliHandler], stderr: io.StringIO
    ) -> None:
        """解析エラーのメッセージが注入済みのstderrへ書き込まれることを確認する。"""
        handler = handler_factory()
        handler.run(["generate"])
        assert "エラー" in stderr.getvalue()


class TestHelpAndVersion:
    """`-h`/`--help`/`--version`に関するテスト（argparseの標準出力を使うためcapsysで検証する）。"""

    def test_help_exits_with_code_zero(
        self,
        handler_factory: Callable[..., CliHandler],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`--help`が終了コード0で完了することを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["--help"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "usage" in captured.out.lower()

    def test_no_arguments_shows_help_and_exits_with_code_zero(
        self,
        handler_factory: Callable[..., CliHandler],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """引数なしで実行した場合、ヘルプを表示して終了コード0になることを確認する。"""
        handler = handler_factory()
        exit_code = handler.run([])
        assert exit_code == 0

    def test_version_exits_with_code_zero(
        self,
        handler_factory: Callable[..., CliHandler],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`--version`が終了コード0で完了することを確認する。"""
        handler = handler_factory()
        exit_code = handler.run(["--version"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "vtotp" in captured.out


class TestKeyManagerIntegration:
    """CliHandlerが実際のKeyManagerと整合していることを確認するテスト。"""

    def test_default_key_manager_matches_max_rotated_keys_constant(self) -> None:
        """CliHandlerが依存するKeyManagerの世代数上限が3であることを確認する（DESIGN.md準拠）。"""
        assert KeyManager.MAX_ROTATED_KEYS == 3


class TestConfigFileHandling:
    """config.jsonの読み込み・パス解決の境界値・異常系に関するテスト。"""

    def test_totp_key_path_environment_variable_is_used_when_cli_key_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """--key未指定でもVTOTP_KEY_PATH環境変数の鍵パスが使われ、コマンドが正常動作することを確認する。

        config.jsonにはkey_pathを一切保存せず、環境変数のみから鍵パスが
        解決されることを明確に示すため、config.json自体を作成しない。
        """
        key_path = tmp_path / "env-master.key"
        storage_path = tmp_path / "env-secrets.enc"

        key_manager = KeyManager()
        key_manager.create_key_file(key_path)
        key_bytes = key_manager.load_key(key_path)
        SecureStorage().save_secrets(
            storage_path,
            key_bytes,
            {"github": SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")},
        )

        monkeypatch.setenv(ENV_KEY_PATH_VARIABLE, str(key_path))

        handler = handler_factory()
        exit_code = handler.run(["list", "--storage", str(storage_path)])

        assert exit_code == 0
        assert "github" in stdout.getvalue()

    def test_cli_key_option_takes_priority_over_environment_variable(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        stdout: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """CLIの`-k`/`--key`がVTOTP_KEY_PATH環境変数より優先されることを確認する。

        環境変数側の鍵で暗号化されたストレージは`--storage`で指定しない
        ため、もしCLI指定が無視され環境変数の鍵が使われてしまった場合は
        復号に失敗し（終了コード4）、優先順位の誤りが明確に検出できる。
        """
        cli_key_path = tmp_path / "cli-master.key"
        cli_storage_path = tmp_path / "cli-secrets.enc"
        env_key_path = tmp_path / "env-master.key"

        cli_key_manager = KeyManager()
        cli_key_manager.create_key_file(cli_key_path)
        SecureStorage().save_secrets(
            cli_storage_path,
            cli_key_manager.load_key(cli_key_path),
            {
                "from-cli": SecretRecord(
                    service_name="from-cli", secret="JBSWY3DPEHPK3PXP"
                )
            },
        )
        # 環境変数側の鍵は、CLI指定の鍵とは異なるバイト列であればよい。
        KeyManager().create_key_file(env_key_path)

        monkeypatch.setenv(ENV_KEY_PATH_VARIABLE, str(env_key_path))

        handler = handler_factory()
        exit_code = handler.run(
            ["list", "-k", str(cli_key_path), "--storage", str(cli_storage_path)]
        )

        assert exit_code == 0
        assert "from-cli" in stdout.getvalue()

    def test_environment_variable_takes_priority_over_config_file(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        stdout: io.StringIO,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VTOTP_KEY_PATH環境変数がconfig.jsonのkey_pathより優先されることを確認する。

        config.json側の鍵で暗号化されたストレージは`--storage`で指定しない
        ため、もし環境変数が無視されconfig.jsonの鍵が使われてしまった場合は
        復号に失敗し（終了コード4）、優先順位の誤りが明確に検出できる。
        """
        config_key_path = tmp_path / "config-master.key"
        env_key_path = tmp_path / "env-master.key"
        env_storage_path = tmp_path / "env-secrets.enc"

        KeyManager().create_key_file(config_key_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps({"key_path": str(config_key_path)}), encoding="utf-8"
        )

        env_key_manager = KeyManager()
        env_key_manager.create_key_file(env_key_path)
        SecureStorage().save_secrets(
            env_storage_path,
            env_key_manager.load_key(env_key_path),
            {
                "from-env": SecretRecord(
                    service_name="from-env", secret="JBSWY3DPEHPK3PXP"
                )
            },
        )

        monkeypatch.setenv(ENV_KEY_PATH_VARIABLE, str(env_key_path))

        handler = handler_factory()
        exit_code = handler.run(["list", "--storage", str(env_storage_path)])

        assert exit_code == 0
        assert "from-env" in stdout.getvalue()

    def test_invalid_json_config_file_is_treated_as_empty(
        self,
        handler_factory: Callable[..., CliHandler],
        config_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """config.jsonがJSONとして解析できない場合、空の設定として扱われることを確認する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("{not valid json", encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "未設定" in stdout.getvalue()

    def test_non_object_json_config_file_is_treated_as_empty(
        self,
        handler_factory: Callable[..., CliHandler],
        config_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """config.jsonのトップレベルがオブジェクトでない場合、空の設定として扱われることを確認する。"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("[]", encoding="utf-8")

        handler = handler_factory()
        exit_code = handler.run(["config"])
        assert exit_code == 0
        assert "未設定" in stdout.getvalue()

    def test_explicit_storage_option_overrides_config_and_default(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
        tmp_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """`--storage`を明示指定した場合、そのパスが暗号化データファイルとして使われることを確認する。"""
        _, key_path = initialized_handler
        custom_storage = tmp_path / "custom" / "secrets.enc"
        SecureStorage().initialize(custom_storage, key_path.read_bytes())

        add_handler = handler_factory()
        exit_code = add_handler.run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--storage",
                str(custom_storage),
                "--secret",
                "JBSWY3DPEHPK3PXP",
            ]
        )
        assert exit_code == 0
        assert custom_storage.is_file()

        list_handler = handler_factory()
        exit_code = list_handler.run(
            ["list", "--key", str(key_path), "--storage", str(custom_storage)]
        )
        assert exit_code == 0
        assert "github" in stdout.getvalue()

    def test_storage_path_from_config_file_is_used_when_cli_option_omitted(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        stdout: io.StringIO,
    ) -> None:
        """config.jsonにstorage_pathが設定済みの場合、そのパスが使われることを確認する。"""
        key_path = tmp_path / "master.key"
        custom_storage = tmp_path / "configured" / "secrets.enc"

        init_handler = handler_factory()
        assert init_handler.run(["init", "--key", str(key_path)]) == 0
        SecureStorage().initialize(custom_storage, key_path.read_bytes())

        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["storage_path"] = str(custom_storage)
        config_path.write_text(json.dumps(config), encoding="utf-8")

        add_handler = handler_factory()
        exit_code = add_handler.run(
            ["add", "github", "--key", str(key_path), "--secret", "JBSWY3DPEHPK3PXP"]
        )
        assert exit_code == 0
        assert custom_storage.is_file()

        list_handler = handler_factory()
        list_handler.run(["list", "--key", str(key_path)])
        assert "github" in stdout.getvalue()

    def test_save_key_path_failure_propagates_and_cleans_up_temp_file(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
        config_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """config.json保存（_save_key_path）でos.replaceが失敗した場合、例外が伝播し一時ファイルが残らないことを確認する。"""
        key_path = tmp_path / "master.key"

        def _raise_os_error(*args: object, **kwargs: object) -> None:
            raise OSError("simulated replace failure")

        monkeypatch.setattr(os, "replace", _raise_os_error)

        handler = handler_factory()
        with pytest.raises(OSError):
            handler._save_key_path(key_path)

        assert not config_path.exists()
        leftover = [
            entry
            for entry in config_path.parent.iterdir()
            if entry.name.startswith(".config.")
        ]
        assert leftover == []


class TestExitCodeFromSystemExit:
    """CliHandler._exit_code_from_system_exit（SystemExit→終了コード変換）に関するテスト。"""

    def test_none_code_maps_to_zero(self) -> None:
        """SystemExit(None)が終了コード0へ変換されることを確認する。"""
        assert CliHandler._exit_code_from_system_exit(SystemExit(None)) == 0

    def test_integer_code_is_returned_as_is(self) -> None:
        """整数の終了コードがそのまま返されることを確認する。"""
        assert CliHandler._exit_code_from_system_exit(SystemExit(2)) == 2

    def test_non_integer_code_maps_to_one(self) -> None:
        """文字列など整数でない終了コードが一般エラー(1)へ変換されることを確認する。"""
        assert CliHandler._exit_code_from_system_exit(SystemExit("some message")) == 1


class TestInteractivePromptEofHandling:
    """対話入力が枯渇（EOF）した場合のフォールバック挙動に関するテスト。"""

    def test_confirm_treats_eof_as_rejection(
        self,
        handler_factory: Callable[..., CliHandler],
        tmp_path: Path,
    ) -> None:
        """確認プロンプトでEOFになった場合、拒否（キャンセル）として扱われることを確認する。"""
        key_path = tmp_path / "master.key"
        key_path.write_bytes(b"\x00" * 32)

        # 2段階警告の1回目の応答すら得られずEOFになるケース。
        handler = handler_factory([])
        exit_code = handler.run(["init", "--key", str(key_path)])
        assert exit_code == 7

    def test_prompt_for_key_output_path_treats_eof_as_cancel(
        self, handler_factory: Callable[..., CliHandler]
    ) -> None:
        """鍵出力先パスの対話入力でEOFになった場合、キャンセルとして扱われることを確認する。"""
        handler = handler_factory([])
        exit_code = handler.run(["init"])
        assert exit_code == 7

    def test_prompt_for_secret_treats_eof_as_cancel(
        self,
        handler_factory: Callable[..., CliHandler],
        initialized_handler: tuple[CliHandler, Path],
    ) -> None:
        """シークレットの対話入力でEOFになった場合、キャンセルとして扱われることを確認する。"""
        _, key_path = initialized_handler
        handler = handler_factory([])
        exit_code = handler.run(["add", "github", "--key", str(key_path)])
        assert exit_code == 7
