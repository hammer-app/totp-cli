"""CLIコマンドのフルライフサイクルに関するE2E/統合テスト。

`python -m vtotp` を実際にサブプロセスとして起動し、実運用の利用者に
近い形で一連のコマンド（``init``/``add``/``list``/``generate``/``rekey``/
``remove``）とエラー経路・終了コードを検証する。``HOME``/``USERPROFILE``
をテストごとに隔離したディレクトリへ差し替えることで、``CliHandler``が
既定で参照する ``~/.totp-cli`` を一切変更しない。
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

import pytest

#: サブプロセス1回あたりのタイムアウト秒数。
_SUBPROCESS_TIMEOUT_SECONDS = 30

#: 本テストスイート全体で使い回す、有効なBase32形式のダミーTOTPシークレット。
_GITHUB_SECRET = "JBSWY3DPEHPK3PXP"
_AWS_SECRET = "KRSXG5CTMVRXEZLU"


def _run_cli(
    args: Sequence[str],
    home_dir: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """``python -m vtotp`` をサブプロセスとして実行し、結果を返す。

    ``HOME``/``USERPROFILE`` を ``home_dir`` へ差し替えることで、
    ``CliHandler`` が既定で使用する ``Path.home() / ".totp-cli"``
    （config.json・暗号化ストレージの既定配置先）を隔離し、実際の
    ユーザーのホームディレクトリを一切変更しないようにする。

    プロンプトが誤って発生した場合にサブプロセスが無限に待機しないよう、
    標準入力には常に空文字列を渡す（即座にEOFとして扱われる）。
    """
    env = os.environ.copy()
    env["HOME"] = str(home_dir)
    env["USERPROFILE"] = str(home_dir)
    env.pop("TOTP_KEY_PATH", None)
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [sys.executable, "-m", "vtotp", *args],
        cwd=home_dir,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        input="",
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )


@pytest.fixture
def home_dir(tmp_path: Path) -> Path:
    """テストごとに隔離された、実際のユーザーホームディレクトリの代わりとなるパスを返す。"""
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    return isolated_home


class TestFullLifecycle:
    """init→add→list→generate→rekey→removeの一連のライフサイクルに関するテスト。"""

    def test_full_lifecycle_succeeds_end_to_end(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """フルライフサイクルを通して各コマンドが期待どおりに動作することを確認する。"""
        key_path = tmp_path / "master.key"
        session_log: list[subprocess.CompletedProcess[str]] = []

        def run(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
            result = _run_cli(args, home_dir)
            session_log.append(result)
            return result

        # 1. init: 新規鍵および暗号化ストレージを作成する。
        result = run(["init", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        assert key_path.is_file()
        assert len(key_path.read_bytes()) == 32

        config_path = home_dir / ".totp-cli" / "config.json"
        storage_path = home_dir / ".totp-cli" / "totp-secrets.enc"
        assert config_path.is_file()
        assert storage_path.is_file()

        # 2. add: 複数サービス（github, aws）を登録する。
        result = run(
            [
                "add",
                "github",
                "--key",
                str(key_path),
                "--secret",
                _GITHUB_SECRET,
                "--issuer",
                "GitHub",
            ]
        )
        assert result.returncode == 0, result.stderr

        result = run(["add", "aws", "--key", str(key_path), "--secret", _AWS_SECRET])
        assert result.returncode == 0, result.stderr

        # 3. list: 昇順・シークレット非表示で一覧が出力されることを確認する。
        result = run(["list", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        service_lines = [
            line
            for line in result.stdout.splitlines()
            if line.strip() and not line.upper().startswith("SERVICE")
        ]
        service_names_in_order = [line.split()[0] for line in service_lines]
        assert service_names_in_order == sorted(service_names_in_order)
        assert "aws" in service_names_in_order
        assert "github" in service_names_in_order
        assert _GITHUB_SECRET not in result.stdout
        assert _AWS_SECRET not in result.stdout

        # 4. generate: 6桁のTOTPコードがstdoutへ出力されることを確認する。
        result = run(["generate", "github", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        code = result.stdout.strip()
        assert code.isdigit()
        assert len(code) == 6

        # 5. rekey: 鍵をローテーションする。
        old_key_bytes = key_path.read_bytes()
        result = run(["rekey", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr

        new_key_bytes = key_path.read_bytes()
        assert new_key_bytes != old_key_bytes
        assert len(new_key_bytes) == 32

        backup_key_path = Path(f"{key_path}.1")
        assert backup_key_path.is_file()
        assert backup_key_path.read_bytes() == old_key_bytes

        # rekey後、新鍵で既存データが引き続き読み出せることを確認する。
        result = run(["list", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        assert "github" in result.stdout
        assert "aws" in result.stdout

        result = run(["generate", "github", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

        # 6. remove: 指定サービスを削除し、listから消えることを確認する。
        result = run(["remove", "github", "--force", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr

        result = run(["list", "--key", str(key_path)])
        assert result.returncode == 0, result.stderr
        remaining_names = [
            line.split()[0]
            for line in result.stdout.splitlines()
            if line.strip() and not line.upper().startswith("SERVICE")
        ]
        assert "github" not in remaining_names
        assert "aws" in remaining_names

        # Zero Leakage Rule: セッション全体のstdout/stderrに、平文シークレットや
        # 生鍵バイト列（旧鍵・新鍵）が一切現れないことを確認する。
        combined_log = "".join(proc.stdout + proc.stderr for proc in session_log)
        assert _GITHUB_SECRET not in combined_log
        assert _AWS_SECRET not in combined_log
        assert old_key_bytes.hex() not in combined_log
        assert new_key_bytes.hex() not in combined_log


class TestArgumentAndEnvironmentIntegration:
    """`-k`/`--key`とTOTP_KEY_PATH環境変数の統合シナリオに関するテスト。"""

    def test_short_key_option_works_across_the_command_sequence(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """`-k`による明示的な鍵パス指定で一連のコマンドが正しく動作することを確認する。"""
        key_path = tmp_path / "master.key"

        assert _run_cli(["init", "-k", str(key_path)], home_dir).returncode == 0
        assert (
            _run_cli(
                ["add", "github", "-k", str(key_path), "--secret", _GITHUB_SECRET],
                home_dir,
            ).returncode
            == 0
        )

        result = _run_cli(["generate", "github", "-k", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

    def test_subcommand_omission_fallback_generates_code(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """サービス名のみ（サブコマンド省略形）を渡した場合、自動的にgenerateとして
        実行され、終了コード0で6桁のTOTPコードが出力されることを確認する。
        """
        key_path = tmp_path / "master.key"

        assert _run_cli(["init", "-k", str(key_path)], home_dir).returncode == 0
        assert (
            _run_cli(
                ["add", "github", "-k", str(key_path), "--secret", _GITHUB_SECRET],
                home_dir,
            ).returncode
            == 0
        )

        result = _run_cli(["github", "-k", str(key_path)], home_dir)
        assert result.returncode == 0, result.stderr
        code = result.stdout.strip()
        assert code.isdigit()
        assert len(code) == 6

    def test_totp_key_path_environment_variable_drives_full_sequence(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """TOTP_KEY_PATH環境変数を設定した状態で、`--key`省略のまま一連のコマンドが動作することを確認する。"""
        key_path = tmp_path / "env-master.key"

        # initはconfig.jsonのkey_pathも更新するため、初回のみ--keyで明示する。
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        env_override = {"TOTP_KEY_PATH": str(key_path)}

        result = _run_cli(
            ["add", "github", "--secret", _GITHUB_SECRET],
            home_dir,
            extra_env=env_override,
        )
        assert result.returncode == 0, result.stderr

        result = _run_cli(["list"], home_dir, extra_env=env_override)
        assert result.returncode == 0, result.stderr
        assert "github" in result.stdout

        result = _run_cli(["generate", "github"], home_dir, extra_env=env_override)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip().isdigit()

        result = _run_cli(
            ["remove", "github", "--force"], home_dir, extra_env=env_override
        )
        assert result.returncode == 0, result.stderr


class TestErrorHandlingExitCodes:
    """エラーハンドリングおよび終了コードに関するテスト。"""

    def test_generate_on_missing_service_returns_exit_code_5(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """未登録のサービスへのgenerateが終了コード5になることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["generate", "unknown-service", "--key", str(key_path)], home_dir
        )
        assert result.returncode == 5

    def test_remove_on_missing_service_returns_exit_code_5(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """未登録のサービスへのremoveが終了コード5になることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        result = _run_cli(
            ["remove", "unknown-service", "--force", "--key", str(key_path)], home_dir
        )
        assert result.returncode == 5

    def test_add_with_invalid_base32_secret_returns_exit_code_6(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """不正なBase32シークレットでのaddが終了コード6になり、入力した不正な値が
        stdout/stderrのいずれにも含まれないことを確認する（Zero Leakage Rule）。
        """
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0

        invalid_secret = "not-valid-base32!!!"
        result = _run_cli(
            ["add", "github", "--key", str(key_path), "--secret", invalid_secret],
            home_dir,
        )
        assert result.returncode == 6
        assert invalid_secret not in result.stdout
        assert invalid_secret not in result.stderr

    def test_corrupted_storage_returns_exit_code_4(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """暗号化ストレージファイルが1バイト改ざんされている場合、generateが終了コード4になることを確認する。"""
        key_path = tmp_path / "master.key"
        assert _run_cli(["init", "--key", str(key_path)], home_dir).returncode == 0
        assert (
            _run_cli(
                ["add", "github", "--key", str(key_path), "--secret", _GITHUB_SECRET],
                home_dir,
            ).returncode
            == 0
        )

        storage_path = home_dir / ".totp-cli" / "totp-secrets.enc"
        document = json.loads(storage_path.read_text(encoding="utf-8"))
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[0] ^= 0xFF
        document["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
        storage_path.write_text(json.dumps(document), encoding="utf-8")

        result = _run_cli(["generate", "github", "--key", str(key_path)], home_dir)
        assert result.returncode == 4

    def test_running_without_an_existing_key_returns_exit_code_3(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """存在しない鍵ファイルを指定した実行が終了コード3になることを確認する（initなし）。"""
        missing_key_path = tmp_path / "does-not-exist.key"

        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path)], home_dir
        )
        assert result.returncode == 3

    def test_error_messages_are_written_to_stderr_not_stdout(
        self, home_dir: Path, tmp_path: Path
    ) -> None:
        """エラー発生時、標準出力ではなく標準エラー出力へメッセージが書かれることを確認する。"""
        missing_key_path = tmp_path / "does-not-exist.key"

        result = _run_cli(
            ["generate", "github", "--key", str(missing_key_path)], home_dir
        )
        assert result.returncode == 3
        assert result.stdout == ""
        assert result.stderr.strip() != ""
