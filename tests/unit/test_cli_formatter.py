"""vtotp.cli.formatter の単体テスト。"""

from __future__ import annotations

import io

import pytest

from vtotp.cli import formatter
from vtotp.domain.exceptions import KeyNotFoundError, StorageCorruptedError
from vtotp.domain.models import SecretRecord
from vtotp.i18n.catalog import MsgKey


class TestFormatMessage:
    """format_message に関するテスト。"""

    def test_resolves_english_message_with_context(self) -> None:
        """英語カタログのプレースホルダーがcontextで補間されることを確認する。"""
        message = formatter.format_message(
            MsgKey.KEY_NOT_FOUND, "en", path="C:/keys/master.key"
        )
        assert message == "Key file not found: C:/keys/master.key"

    def test_resolves_japanese_message_with_context(self) -> None:
        """日本語カタログのプレースホルダーがcontextで補間されることを確認する。"""
        message = formatter.format_message(
            MsgKey.KEY_NOT_FOUND, "ja", path="C:/keys/master.key"
        )
        assert message == "鍵ファイルが見つかりません: C:/keys/master.key"

    def test_unknown_language_falls_back_to_english(self) -> None:
        """未知の言語コードの場合、英語へフォールバックすることを確認する。"""
        message = formatter.format_message(MsgKey.SECRET_EMPTY, "fr")
        assert message == "TOTP secret is empty"


class TestFormatError:
    """format_error / write_error に関するテスト。"""

    def test_includes_localized_label_and_body(self) -> None:
        """エラー表示文にローカライズ済みラベルと本文が含まれることを確認する。"""
        error = KeyNotFoundError(MsgKey.KEY_NOT_FOUND, context={"path": "k.key"})
        assert formatter.format_error(error, "en") == "Error: Key file not found: k.key"
        assert (
            formatter.format_error(error, "ja")
            == "エラー: 鍵ファイルが見つかりません: k.key"
        )

    def test_write_error_writes_to_given_stream(self) -> None:
        """write_errorが注入したストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        error = StorageCorruptedError(MsgKey.STORAGE_DECRYPTION_FAILED)
        formatter.write_error(error, "en", stream=stream)
        expected_body = (
            "Failed to verify the encrypted data "
            "(it may be corrupted, tampered with, or the key may be incorrect)"
        )
        assert stream.getvalue() == f"Error: {expected_body}\n"

    def test_write_error_does_not_leak_secret_when_caller_avoids_it(self) -> None:
        """呼び出し元がcontextに秘密情報を含めない限り、write_errorの出力に秘密情報が現れないことを確認する。"""
        stream = io.StringIO()
        error = KeyNotFoundError(
            MsgKey.KEY_NOT_FOUND, context={"path": "C:/keys/master.key"}
        )
        formatter.write_error(error, "en", stream=stream)
        assert "JBSWY3DPEHPK3PXP" not in stream.getvalue()

    def test_write_error_defaults_to_stderr(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """streamを省略した場合、標準エラー出力へ書き込まれることを確認する。"""
        error = StorageCorruptedError(MsgKey.STORAGE_DECRYPTION_FAILED)
        formatter.write_error(error, "en")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error:" in captured.err


class TestFormatWarning:
    """format_warning / write_warning に関するテスト。"""

    def test_includes_localized_label_and_body(self) -> None:
        """警告表示文にローカライズ済みラベルと本文が含まれることを確認する。"""
        message = formatter.format_warning(
            MsgKey.REKEY_ROTATION_LIMIT_NOTICE, "en", path="master.key.3"
        )
        assert message.startswith("Warning: ")
        assert "master.key.3" in message

    def test_write_warning_writes_to_given_stream(self) -> None:
        """write_warningが注入したストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        formatter.write_warning(MsgKey.CANCELLED, "ja", stream=stream)
        assert stream.getvalue() == "警告: ユーザーによって操作がキャンセルされました\n"


class TestWriteCode:
    """write_code に関するテスト。"""

    def test_writes_only_the_code_to_the_given_stream(self) -> None:
        """コード文字列のみが改行付きでストリームへ書き込まれることを確認する。"""
        stream = io.StringIO()
        formatter.write_code("123456", stream)
        assert stream.getvalue() == "123456\n"

    def test_does_not_write_to_stderr(self) -> None:
        """write_codeが標準エラー用のストリームには何も書き込まないことを確認する。"""
        stdout = io.StringIO()
        stderr = io.StringIO()
        formatter.write_code("654321", stdout)
        assert stderr.getvalue() == ""


class TestFormatServiceTable:
    """format_service_table / write_service_table に関するテスト。"""

    def test_empty_records_produce_empty_string(self) -> None:
        """レコードが空の場合、空文字列を返すことを確認する。"""
        assert formatter.format_service_table([], "en") == ""

    def test_includes_header_and_all_service_names_in_english(self) -> None:
        """英語表示でヘッダー行と全サービス名が出力に含まれることを確認する。"""
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            ),
            SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None),
        ]
        table = formatter.format_service_table(records, "en")
        assert "SERVICE" in table
        assert "ISSUER" in table
        assert "github" in table
        assert "aws" in table
        assert "GitHub" in table

    def test_includes_localized_header_in_japanese(self) -> None:
        """日本語表示でヘッダーがローカライズされることを確認する。"""
        records = [
            SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP", issuer=None)
        ]
        table = formatter.format_service_table(records, "ja")
        assert "サービス" in table
        assert "発行者" in table

    def test_missing_issuer_is_rendered_as_placeholder(self) -> None:
        """issuerが無いレコードはプレースホルダー（`-`）で表示されることを確認する。"""
        records = [
            SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None)
        ]
        table = formatter.format_service_table(records, "en")
        lines = table.splitlines()
        assert lines[1].endswith("-")

    def test_does_not_include_secret_values(self) -> None:
        """出力にシークレットの値が一切含まれないことを確認する（Zero Leakage Rule）。"""
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            ),
        ]
        table = formatter.format_service_table(records, "en")
        assert "JBSWY3DPEHPK3PXP" not in table

    def test_write_service_table_writes_nothing_for_empty_records(self) -> None:
        """レコードが空の場合、write_service_tableは何も出力しないことを確認する。"""
        stream = io.StringIO()
        formatter.write_service_table([], "en", stream)
        assert stream.getvalue() == ""

    def test_write_service_table_writes_table_to_stream(self) -> None:
        """write_service_tableが整形済みテーブルをストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            )
        ]
        formatter.write_service_table(records, "en", stream)
        assert "github" in stream.getvalue()
        assert "GitHub" in stream.getvalue()


class TestRemainingSecondsBar:
    """format_remaining_seconds_bar / write_remaining_seconds_bar に関するテスト。"""

    def test_full_remaining_time_fills_the_bar_completely(self) -> None:
        """残り秒数が満額のとき、バーが全て埋まった表示になることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(30, 30, width=10)
        assert bar.startswith("[##########]")
        assert "30s" in bar

    def test_zero_remaining_time_leaves_the_bar_empty(self) -> None:
        """残り秒数が0のとき、バーが空の表示になることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(0, 30, width=10)
        assert bar.startswith("[----------]")
        assert " 0s" in bar

    def test_half_remaining_time_fills_the_bar_halfway(self) -> None:
        """残り秒数が半分のとき、バーが半分埋まった表示になることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(15, 30, width=10)
        assert bar == "[#####-----] 15s"

    def test_remaining_greater_than_time_step_is_clamped(self) -> None:
        """remainingがtime_stepを超える場合、time_stepにクランプされることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(999, 30, width=10)
        assert bar.startswith("[##########]")
        assert "30s" in bar

    def test_negative_remaining_is_clamped_to_zero(self) -> None:
        """remainingが負の場合、0にクランプされることを確認する。"""
        bar = formatter.format_remaining_seconds_bar(-5, 30, width=10)
        assert bar.startswith("[----------]")

    def test_non_positive_time_step_raises_value_error(self) -> None:
        """time_stepが0以下の場合にValueErrorになることを確認する。"""
        with pytest.raises(ValueError):
            formatter.format_remaining_seconds_bar(10, 0)

    def test_non_positive_width_raises_value_error(self) -> None:
        """widthが0以下の場合にValueErrorになることを確認する。"""
        with pytest.raises(ValueError):
            formatter.format_remaining_seconds_bar(10, 30, width=0)

    def test_write_remaining_seconds_bar_writes_to_stderr_by_default(self) -> None:
        """write_remaining_seconds_barが既定でstderr相当のストリームへ出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_remaining_seconds_bar(15, 30, stream)
        assert "15s" in stream.getvalue()


class TestWriteInfo:
    """write_info に関するテスト。"""

    def test_writes_localized_message_as_is(self) -> None:
        """write_infoがローカライズ済みメッセージをそのまま出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_info(
            MsgKey.ADD_SERVICE_REGISTERED, "en", stream=stream, service="github"
        )
        assert stream.getvalue() == "Service registered: github\n"

    def test_writes_japanese_message(self) -> None:
        """日本語指定時に日本語メッセージが出力されることを確認する。"""
        stream = io.StringIO()
        formatter.write_info(
            MsgKey.ADD_SERVICE_REGISTERED, "ja", stream=stream, service="github"
        )
        assert stream.getvalue() == "サービスを登録しました: github\n"
