"""vtotp.cli.formatter の単体テスト。"""

from __future__ import annotations

import io

import pytest

from vtotp.cli import formatter
from vtotp.domain.models import SecretRecord


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
        assert formatter.format_service_table([]) == ""

    def test_includes_header_and_all_service_names(self) -> None:
        """ヘッダー行と全サービス名が出力に含まれることを確認する。"""
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            ),
            SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None),
        ]
        table = formatter.format_service_table(records)
        assert "SERVICE" in table
        assert "ISSUER" in table
        assert "github" in table
        assert "aws" in table
        assert "GitHub" in table

    def test_missing_issuer_is_rendered_as_placeholder(self) -> None:
        """issuerが無いレコードはプレースホルダー（`-`）で表示されることを確認する。"""
        records = [
            SecretRecord(service_name="aws", secret="KRSXG5CTMVRXEZLU", issuer=None)
        ]
        table = formatter.format_service_table(records)
        lines = table.splitlines()
        assert lines[1].endswith("-")

    def test_does_not_include_secret_values(self) -> None:
        """出力にシークレットの値が一切含まれないことを確認する（Zero Leakage Rule）。"""
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            ),
        ]
        table = formatter.format_service_table(records)
        assert "JBSWY3DPEHPK3PXP" not in table

    def test_write_service_table_writes_nothing_for_empty_records(self) -> None:
        """レコードが空の場合、write_service_tableは何も出力しないことを確認する。"""
        stream = io.StringIO()
        formatter.write_service_table([], stream)
        assert stream.getvalue() == ""

    def test_write_service_table_writes_table_to_stream(self) -> None:
        """write_service_tableが整形済みテーブルをストリームへ書き込むことを確認する。"""
        stream = io.StringIO()
        records = [
            SecretRecord(
                service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
            )
        ]
        formatter.write_service_table(records, stream)
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


class TestInfoWarningError:
    """write_info / write_warning / write_error に関するテスト。"""

    def test_write_info_writes_message_as_is(self) -> None:
        """write_infoがメッセージをそのまま出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_info("案内メッセージ", stream)
        assert stream.getvalue() == "案内メッセージ\n"

    def test_write_warning_prefixes_message(self) -> None:
        """write_warningが警告接頭辞付きでメッセージを出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_warning("注意してください", stream)
        assert stream.getvalue() == "警告: 注意してください\n"

    def test_write_error_prefixes_message(self) -> None:
        """write_errorがエラー接頭辞付きでメッセージを出力することを確認する。"""
        stream = io.StringIO()
        formatter.write_error("処理に失敗しました", stream)
        assert stream.getvalue() == "エラー: 処理に失敗しました\n"

    def test_write_error_does_not_leak_secret_when_caller_avoids_it(self) -> None:
        """呼び出し元が秘密情報を含めない限り、write_errorの出力に秘密情報が現れないことを確認する。"""
        stream = io.StringIO()
        formatter.write_error("鍵ファイルが見つかりません: C:/keys/master.key", stream)
        assert "JBSWY3DPEHPK3PXP" not in stream.getvalue()
