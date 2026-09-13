"""鍵ファイル（AES-256用マスターキー）の管理を担う KeyManager を定義するモジュール。

DESIGN.md 6章「KeyManager」に基づき、鍵の生成・読み込み・検証・存在確認、
CLI/環境変数/config.jsonからのパス解決、および世代管理（ローテーション）を
提供する。鍵の内容はいかなる場合もログや例外メッセージへ出力しない
（Zero Leakage Rule）。
"""

from __future__ import annotations

import os
import secrets
import stat
import tempfile
from pathlib import Path

from totp_cli.domain.exceptions import InvalidKeyError, KeyNotFoundError


class KeyManager:
    """AES-256用マスターキーファイルの生成・検証・解決・世代管理を行うクラス。

    鍵ファイルは常に `config.json` とは分離された外部パスに保持され、
    このクラス自身は鍵の内容をインスタンス変数として保持しない。
    """

    #: マスターキーの必須サイズ（AES-256のため32バイト）。
    KEY_SIZE_BYTES: int = 32

    #: 保持する鍵ファイルの世代数の上限（`<key_path>.1` 〜 `<key_path>.3`）。
    MAX_ROTATED_KEYS: int = 3

    def generate_key(self) -> bytes:
        """暗号学的に安全な32バイト鍵を生成する。"""
        return secrets.token_bytes(self.KEY_SIZE_BYTES)

    def create_key_file(self, path: Path, key: bytes | None = None) -> None:
        """鍵を生成または受け取り、指定された外部パスへ保存する。

        `key` が指定されない場合は新規に生成する。書き込みは一時ファイル
        経由のatomic置換で行い、書き込み途中の内容が正式パスに現れないよう
        にする。
        """
        actual_key = key if key is not None else self.generate_key()
        if len(actual_key) != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(
                f"鍵のサイズが不正です（{self.KEY_SIZE_BYTES}バイトである必要があります）: {path}"
            )
        self._atomic_write_bytes(path, actual_key)

    def rotate_key_file(self, path: Path, new_key: bytes) -> Path:
        """既存鍵を世代番号付きファイルへ繰り上げ、新鍵を `path` へ保存する。

        `<key_path>.2` -> `<key_path>.3`、`<key_path>.1` -> `<key_path>.2`、
        `path` -> `<key_path>.1` の順に繰り上げたのち、`new_key` を `path`
        へ書き込む。上限到達時（`<key_path>.3` が既に存在する場合）の削除
        可否の確認は、呼び出し元（CliHandler）が事前に対話確認を済ませて
        いることを前提とし、本メソッドは繰り上げ処理のみを行う。
        """
        generations = self.rotated_key_paths(path, self.MAX_ROTATED_KEYS)

        for index in range(len(generations) - 1, 0, -1):
            source = generations[index - 1]
            destination = generations[index]
            if source.exists():
                os.replace(source, destination)

        if path.exists():
            os.replace(path, generations[0])

        self.create_key_file(path, new_key)
        return path

    def rotated_key_paths(self, path: Path, max_generations: int = 3) -> list[Path]:
        """`path.1` から `path.N` までのローテーション対象パスを返す。"""
        return [
            Path(f"{path}.{generation}") for generation in range(1, max_generations + 1)
        ]

    def check_existing_key(self, path: Path) -> bool:
        """指定パスに既存の鍵ファイルがあるか確認する。"""
        return path.is_file()

    def verify_key_file(self, path: Path) -> None:
        """外部指定された既存の鍵ファイルを検証する。

        通常の読み込み処理（generate/get/add等）で、指定された鍵パスに
        既存の鍵ファイルがあること、および形式が正しいことを保証するために
        呼び出す。
        """
        self.validate_key_file(path)

    def load_key(self, path: Path) -> bytes:
        """鍵を読み込み、32バイトであることを検証する。"""
        self.validate_key_file(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise InvalidKeyError(f"鍵ファイルを読み込めません: {path}") from exc

        if len(data) != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(
                f"鍵ファイルのサイズが不正です（{self.KEY_SIZE_BYTES}バイトである必要があります）: {path}"
            )
        return data

    def resolve_key_path(
        self,
        cli_path: Path | None,
        config_path: Path | None,
        environment_path: Path | None,
    ) -> Path:
        """優先順位に従い、実際に使用する鍵ファイルパスを解決する。

        優先順位:
            1. CLIオプション `--key`
            2. 環境変数 `TOTP_KEY_PATH`
            3. `config.json` の `key_path`
            4. いずれも未指定の場合はエラー
        """
        if cli_path is not None:
            return cli_path
        if environment_path is not None:
            return environment_path
        if config_path is not None:
            return config_path
        raise KeyNotFoundError(
            "鍵ファイルのパスが指定されていません"
            "（--key、TOTP_KEY_PATH、config.jsonのいずれにも指定がありません）"
        )

    def validate_key_file(self, path: Path) -> None:
        """存在、通常ファイル、サイズ、読み取り可否を検証する。"""
        if not path.exists():
            raise KeyNotFoundError(f"鍵ファイルが見つかりません: {path}")
        if not path.is_file():
            raise InvalidKeyError(f"鍵ファイルが通常のファイルではありません: {path}")
        if path.stat().st_size != self.KEY_SIZE_BYTES:
            raise InvalidKeyError(
                f"鍵ファイルのサイズが不正です（{self.KEY_SIZE_BYTES}バイトである必要があります）: {path}"
            )
        if not os.access(path, os.R_OK):
            raise InvalidKeyError(f"鍵ファイルを読み取る権限がありません: {path}")

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        """一時ファイルへ書き込んだのち `os.replace` で正式パスへatomicに置換する。

        書き込み途中のプロセス終了によって既存の鍵ファイルが破壊されない
        ようにするための内部ヘルパー。
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            self._restrict_permissions(tmp_path)
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def _restrict_permissions(self, path: Path) -> None:
        """可能な環境でのみ、鍵ファイルの権限を所有者のみの読み書きに制限する。

        Unix系では0600相当に設定する。Windows等、権限モデルが異なる環境
        では失敗しても致命的ではないため、エラーは無視する。
        """
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
