"""CLI全体のエントリーポイントである CliHandler を定義するモジュール。

DESIGN.md 11〜14章に基づき、CLI引数の前処理（省略形フォールバック）、
argparseによるサブコマンド解析、各サブコマンドのユースケース実行、
および例外の終了コードへの変換を担う。TOTPシークレットや鍵の内容は
いかなる場合もstdout/stderrへ出力しない（Zero Leakage Rule）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import IO, Callable, NoReturn, Sequence

from totp_cli import __version__
from totp_cli.cli import formatter
from totp_cli.core.key_manager import KeyManager
from totp_cli.core.secure_storage import SecureStorage
from totp_cli.core.service_registry import ServiceRegistry
from totp_cli.core.totp_generator import TotpGenerator
from totp_cli.domain.exceptions import (
    CancelledError,
    CommandParseError,
    KeyNotFoundError,
    TotpCliError,
)
from totp_cli.domain.models import SecretRecord

#: config.json / 暗号化データファイルの既定の配置ディレクトリ。
DEFAULT_CONFIG_DIR: Path = Path.home() / ".totp-cli"

#: config.jsonの既定パス。
DEFAULT_CONFIG_PATH: Path = DEFAULT_CONFIG_DIR / "config.json"

#: config.jsonにstorage_pathが未設定の場合に使用する既定の暗号化データファイル名。
DEFAULT_STORAGE_FILENAME: str = "totp-secrets.enc"

#: 鍵ファイルパスを指定する環境変数名。
ENV_KEY_PATH_VARIABLE: str = "TOTP_KEY_PATH"


class _ArgumentParser(argparse.ArgumentParser):
    """argparseの既定のexit動作を無効化し、CommandParseErrorへ変換するパーサー。

    標準の :class:`argparse.ArgumentParser` は解析エラー時に使用方法を
    表示して ``sys.exit(2)`` を呼び出すが、CliHandlerが一貫した例外処理・
    終了コード変換フローを提供できるよう、代わりに :class:`CommandParseError`
    を送出する。
    """

    error_stream: IO[str]

    def error(self, message: str) -> NoReturn:
        """使用方法を表示したうえで、CommandParseErrorを送出する。"""
        self.print_usage(self.error_stream)
        raise CommandParseError(message)


class CliHandler:
    """CLI全体のエントリーポイントを提供するクラス。

    CLI引数の初期取得・省略形コマンドの判定・argparseによる正式な引数
    解析・コマンドディスパッチ・例外のユーザー向けメッセージへの変換を
    行う。
    """

    #: 省略形フォールバックの対象外とする予約済みトークン（サブコマンド名・エイリアス・グローバルオプション）。
    RESERVED_COMMANDS: frozenset[str] = frozenset(
        {
            "init",
            "generate",
            "get",
            "-g",
            "add",
            "remove",
            "rm",
            "list",
            "ls",
            "rekey",
            "config",
            "-h",
            "--help",
            "--version",
        }
    )

    def __init__(
        self,
        key_manager: KeyManager | None = None,
        secure_storage: SecureStorage | None = None,
        service_registry: ServiceRegistry | None = None,
        totp_generator: TotpGenerator | None = None,
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
        input_func: Callable[[], str] | None = None,
        config_path: Path | None = None,
    ) -> None:
        """依存コンポーネントと入出力ストリームを設定する。

        いずれの引数も省略可能で、省略時は実運用向けの既定値（実際の
        コアコンポーネント、``sys.stdout``/``sys.stderr``、組み込みの
        ``input``、既定のconfig.jsonパス）が使用される。テストからは
        これらを注入してふるまいを検証できる。
        """
        self._key_manager = key_manager if key_manager is not None else KeyManager()
        self._secure_storage = (
            secure_storage if secure_storage is not None else SecureStorage()
        )
        self._service_registry = (
            service_registry if service_registry is not None else ServiceRegistry()
        )
        self._totp_generator = (
            totp_generator if totp_generator is not None else TotpGenerator()
        )
        self._stdout: IO[str] = stdout if stdout is not None else sys.stdout
        self._stderr: IO[str] = stderr if stderr is not None else sys.stderr
        self._input: Callable[[], str] = input_func if input_func is not None else input
        self._config_path = (
            config_path if config_path is not None else DEFAULT_CONFIG_PATH
        )

        self._parser = self._build_parser()
        self._command_handlers: dict[str, Callable[[argparse.Namespace], int]] = {
            "init": self._cmd_init,
            "generate": self._cmd_generate,
            "get": self._cmd_generate,
            "add": self._cmd_add,
            "list": self._cmd_list,
            "ls": self._cmd_list,
            "remove": self._cmd_remove,
            "rm": self._cmd_remove,
            "rekey": self._cmd_rekey,
            "config": self._cmd_config,
        }

    # --- エントリーポイント ---

    def run(self, argv: Sequence[str]) -> int:
        """CLI全体のエントリーポイント。

        引数の正規化・解析・ディスパッチ・エラー処理を行い、終了コード
        を返す。``-h``/``--help``/``--version`` はargparseの標準的な挙動
        に従い、実際の標準出力・標準エラー出力（``sys.stdout``/
        ``sys.stderr``）へ直接書き込む。それ以外のコマンド結果・エラー
        メッセージは、コンストラクタで注入されたストリームへ書き込む。
        """
        normalized_argv = self.normalize_argv(list(argv))
        try:
            parsed_args = self._parser.parse_args(normalized_argv)
        except SystemExit as exc:
            return self._exit_code_from_system_exit(exc)
        except CommandParseError as error:
            formatter.write_error(str(error), self._stderr)
            return error.exit_code

        try:
            return self._command_handlers[parsed_args.command](parsed_args)
        except TotpCliError as error:
            formatter.write_error(str(error), self._stderr)
            return error.exit_code
        except ValueError as error:
            formatter.write_error(str(error), self._stderr)
            return 1

    @staticmethod
    def _exit_code_from_system_exit(exc: SystemExit) -> int:
        """``SystemExit``（``-h``/``--version``等）から終了コードを取り出す。"""
        if exc.code is None:
            return 0
        if isinstance(exc.code, int):
            return exc.code
        return 1

    def normalize_argv(self, argv: list[str]) -> list[str]:
        """省略形コマンド（サービス名のみの指定）を正式な `generate` コマンドへ変換する。

        第一引数が予約済みトークン（サブコマンド名・エイリアス・
        `-h`/`--help`/`--version` 等のオプション）でない場合、サービス名
        と判定し `generate <service>` へ読み替える。
        """
        if not argv:
            return ["--help"]

        first = argv[0]
        if first == "-g":
            return ["generate", *argv[1:]]
        if first in self.RESERVED_COMMANDS or first.startswith("-"):
            return list(argv)
        return ["generate", first, *argv[1:]]

    # --- argparseパーサー構築 ---

    def _build_parser(self) -> _ArgumentParser:
        """サブコマンド一式を備えたargparseパーサーを構築する。"""
        parser = _ArgumentParser(
            prog="totp-cli",
            description="Custom CLI TOTP Authenticator",
        )
        parser.add_argument(
            "--version", action="version", version=f"%(prog)s {__version__}"
        )

        subparsers = parser.add_subparsers(dest="command")

        init_parser = subparsers.add_parser("init", help="新しい鍵ファイルを作成する")
        init_parser.add_argument("-k", "--key", type=Path, default=None)

        generate_parser = subparsers.add_parser(
            "generate", aliases=["get"], help="TOTPコードを生成して表示する"
        )
        generate_parser.add_argument("service")
        generate_parser.add_argument("-k", "--key", type=Path, default=None)
        generate_parser.add_argument("--storage", type=Path, default=None)

        add_parser = subparsers.add_parser("add", help="新しいサービスを登録する")
        add_parser.add_argument("service")
        add_parser.add_argument("--secret", "-s", default=None)
        add_parser.add_argument("--issuer", default=None)
        add_parser.add_argument("-k", "--key", type=Path, default=None)
        add_parser.add_argument("--storage", type=Path, default=None)

        list_parser = subparsers.add_parser(
            "list", aliases=["ls"], help="登録済みサービスの一覧を表示する"
        )
        list_parser.add_argument("-k", "--key", type=Path, default=None)
        list_parser.add_argument("--storage", type=Path, default=None)

        remove_parser = subparsers.add_parser(
            "remove", aliases=["rm"], help="登録済みサービスを削除する"
        )
        remove_parser.add_argument("service")
        remove_parser.add_argument("--force", "-f", action="store_true")
        remove_parser.add_argument("-k", "--key", type=Path, default=None)
        remove_parser.add_argument("--storage", type=Path, default=None)

        rekey_parser = subparsers.add_parser(
            "rekey", help="鍵を更新し、データを再暗号化する"
        )
        rekey_parser.add_argument("-k", "--key", type=Path, default=None)
        rekey_parser.add_argument("--storage", type=Path, default=None)

        config_parser = subparsers.add_parser(
            "config", help="現在解決される設定内容を表示する"
        )

        # サブパーサーも `_ArgumentParser` のインスタンスであり、それぞれが
        # 独自に `.error()` を呼び出しうるため、全パーサーへ注入済みの
        # stderrストリームを設定する。
        for sub_parser in (
            parser,
            init_parser,
            generate_parser,
            add_parser,
            list_parser,
            remove_parser,
            rekey_parser,
            config_parser,
        ):
            sub_parser.error_stream = self._stderr

        return parser

    # --- パス・設定の解決 ---

    def _load_config(self) -> dict[str, str]:
        """config.jsonを読み込む。存在しない・壊れている場合は空の設定として扱う。"""
        if not self._config_path.is_file():
            return {}
        try:
            data = json.loads(self._config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {key: value for key, value in data.items() if isinstance(value, str)}

    def _save_key_path(self, key_path: Path) -> None:
        """config.jsonの `key_path` のみをatomicに更新する（initでのみ呼び出す）。"""
        config = self._load_config()
        config["key_path"] = str(key_path)

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=self._config_path.parent, prefix=".config.", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(config, tmp_file, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._config_path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def _resolve_key_path(self, cli_key: Path | None) -> Path:
        """CLIオプション・環境変数・config.jsonの優先順位で鍵ファイルパスを解決する。"""
        config = self._load_config()
        config_key_path = Path(config["key_path"]) if "key_path" in config else None
        environment_value = os.environ.get(ENV_KEY_PATH_VARIABLE)
        environment_key_path = Path(environment_value) if environment_value else None
        return self._key_manager.resolve_key_path(
            cli_path=cli_key,
            config_path=config_key_path,
            environment_path=environment_key_path,
        )

    def _resolve_storage_path(self, cli_storage: Path | None) -> Path:
        """CLIオプション・config.jsonの優先順位で暗号化データファイルパスを解決する。

        いずれにも指定が無い場合は、config.jsonと同じディレクトリ内の
        既定ファイル名（`totp-secrets.enc`）を使用する。
        """
        if cli_storage is not None:
            return cli_storage
        config = self._load_config()
        if "storage_path" in config:
            return Path(config["storage_path"])
        return self._config_path.parent / DEFAULT_STORAGE_FILENAME

    # --- 対話入力・確認 ---

    def _cancel(self) -> NoReturn:
        """ユーザーによるキャンセルとして :class:`CancelledError` を送出する。"""
        raise CancelledError("ユーザーによって操作がキャンセルされました")

    def _confirm(self, message: str) -> bool:
        """`message` を表示し、`y`/`yes`（大文字小文字を区別しない）の入力のみを承認として扱う。"""
        formatter.write_info(f"{message} [y/N]: ", self._stderr)
        try:
            response = self._input()
        except EOFError:
            return False
        return response.strip().lower() in {"y", "yes"}

    def _prompt_for_key_output_path(self) -> Path | None:
        """`init` で `--key` 未指定時に、鍵ファイルの出力先を対話入力で取得する。"""
        formatter.write_info(
            "鍵ファイルの新規作成先パスを入力してください（空欄でキャンセル）:",
            self._stderr,
        )
        try:
            response = self._input()
        except EOFError:
            return None
        response = response.strip()
        return Path(response) if response else None

    def _prompt_for_secret(self) -> str | None:
        """`add` で `--secret` 未指定時に、TOTPシークレットを対話入力で取得する。"""
        formatter.write_info(
            "TOTPシークレット（Base32）を入力してください（空欄でキャンセル）:",
            self._stderr,
        )
        try:
            response = self._input()
        except EOFError:
            return None
        response = response.strip()
        return response if response else None

    def _confirm_existing_key_warning(self, path: Path) -> bool:
        """`init` の第1警告：既存鍵ファイルの上書き確認。"""
        return self._confirm(
            f"指定された場所には既に鍵ファイルが存在します: {path}\n新しい鍵で上書きしますか？"
        )

    def _confirm_decryption_loss_warning(self) -> bool:
        """`init` の第2警告：既存の暗号化データを復号できなくなる可能性の確認。"""
        return self._confirm(
            "上書きすると、既存の暗号化データを現在の鍵で復号できなくなる可能性があります。"
            "続行しますか？"
        )

    def _confirm_rotation_limit_warning(self, oldest_path: Path) -> bool:
        """`rekey` のローテーション上限警告：最古世代の鍵ファイル削除確認。"""
        formatter.write_info(
            f"ローテーション上限に達したため、最も古い鍵ファイル {oldest_path} を削除します。",
            self._stderr,
        )
        return self._confirm(
            "この鍵を必要とするバックアップや過去の暗号化データは、"
            "今後復号できなくなる可能性があります。続行しますか？"
        )

    # --- サブコマンド実装 ---

    def _cmd_init(self, args: argparse.Namespace) -> int:
        """新しい鍵ファイルと空の暗号化ストレージを作成し、config.jsonのkey_pathを更新する。"""
        key_output_path: Path | None = args.key
        if key_output_path is None:
            key_output_path = self._prompt_for_key_output_path()
            if key_output_path is None:
                self._cancel()

        if self._key_manager.check_existing_key(key_output_path):
            if not self._confirm_existing_key_warning(key_output_path):
                self._cancel()
            if not self._confirm_decryption_loss_warning():
                self._cancel()

        self._key_manager.create_key_file(key_output_path)
        new_key = self._key_manager.load_key(key_output_path)

        storage_path = self._resolve_storage_path(None)
        self._secure_storage.initialize(storage_path, new_key)

        self._save_key_path(key_output_path)

        formatter.write_info(
            f"鍵ファイルを作成しました: {key_output_path}", self._stderr
        )
        formatter.write_info(
            f"暗号化データファイルを初期化しました: {storage_path}", self._stderr
        )
        return 0

    def _cmd_generate(self, args: argparse.Namespace) -> int:
        """指定されたサービスの現在のTOTPコードを生成し、stdoutへ出力する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)
        record = self._service_registry.get(records, args.service)

        code = self._totp_generator.generate(record.secret)
        formatter.write_code(code, self._stdout)

        remaining = self._totp_generator.remaining_seconds()
        formatter.write_remaining_seconds_bar(
            remaining, self._totp_generator.time_step, self._stderr
        )
        return 0

    def _cmd_add(self, args: argparse.Namespace) -> int:
        """新しいサービスをシークレットとともに登録する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)

        secret: str | None = args.secret
        if secret is None:
            secret = self._prompt_for_secret()
            if secret is None:
                self._cancel()

        normalized_secret = self._totp_generator.validate_secret(secret)
        record = SecretRecord(
            service_name=args.service,
            secret=normalized_secret,
            issuer=args.issuer,
        )
        updated_records = self._service_registry.add(records, record)
        self._secure_storage.save_secrets(storage_path, key, updated_records)

        formatter.write_info(f"サービスを登録しました: {args.service}", self._stderr)
        return 0

    def _cmd_list(self, args: argparse.Namespace) -> int:
        """登録済みサービスの一覧を表形式でstdoutへ出力する。シークレットは出力しない。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)
        names = self._service_registry.list_names(records)
        ordered_records = [records[name] for name in names]
        formatter.write_service_table(ordered_records, self._stdout)
        return 0

    def _cmd_remove(self, args: argparse.Namespace) -> int:
        """指定されたサービスを削除する。`--force` 未指定時は削除前に確認する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        key = self._key_manager.load_key(key_path)
        records = self._secure_storage.load_secrets(storage_path, key)

        # 存在しないサービスの場合はここでServiceNotFoundErrorが送出される。
        self._service_registry.get(records, args.service)

        if not args.force:
            if not self._confirm(
                f"サービス '{args.service}' を削除します。よろしいですか？"
            ):
                self._cancel()

        updated_records = self._service_registry.remove(records, args.service)
        self._secure_storage.save_secrets(storage_path, key, updated_records)

        formatter.write_info(f"サービスを削除しました: {args.service}", self._stderr)
        return 0

    def _cmd_rekey(self, args: argparse.Namespace) -> int:
        """鍵を更新し、既存の暗号化データを新鍵で再暗号化する。"""
        key_path = self._resolve_key_path(args.key)
        storage_path = self._resolve_storage_path(args.storage)

        old_key = self._key_manager.load_key(key_path)
        new_key = self._key_manager.generate_key()

        rotated_paths = self._key_manager.rotated_key_paths(
            key_path, self._key_manager.MAX_ROTATED_KEYS
        )
        if rotated_paths and rotated_paths[-1].exists():
            if not self._confirm_rotation_limit_warning(rotated_paths[-1]):
                self._cancel()

        self._key_manager.rotate_key_file(key_path, new_key)
        self._secure_storage.rekey(storage_path, old_key, new_key)

        formatter.write_info(
            f"鍵を更新し、データを再暗号化しました: {key_path}", self._stderr
        )
        return 0

    def _cmd_config(self, args: argparse.Namespace) -> int:
        """現在解決される設定内容（config.jsonのパス・鍵パス・データパス）を表示する。

        鍵の内容やシークレットは一切表示しない（Zero Leakage Rule）。
        """
        try:
            key_path_display = str(self._resolve_key_path(None))
        except KeyNotFoundError:
            key_path_display = "(未設定)"
        storage_path_display = str(self._resolve_storage_path(None))

        print(f"config_path: {self._config_path}", file=self._stdout)
        print(f"key_path: {key_path_display}", file=self._stdout)
        print(f"storage_path: {storage_path_display}", file=self._stdout)
        return 0
