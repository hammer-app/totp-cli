"""totp_cli.core.totp_generator の単体テスト。

RFC 6238 Appendix B の公式テストベクター、およびBase32シークレットの
正規化・検証ロジックを検証する。
"""

from __future__ import annotations

import base64

import pytest

from totp_cli.core.totp_generator import (
    TotpGenerator,
    generate_totp,
    remaining_seconds,
    validate_secret,
)
from totp_cli.domain.exceptions import InvalidSecretError


def _rfc6238_seed(byte_length: int) -> bytes:
    """RFC 6238 Appendix Bで使用される周期10の数字列シークレットを生成する。"""
    repeated = "1234567890" * ((byte_length // 10) + 1)
    return repeated[:byte_length].encode("ascii")


def _rfc6238_secret(byte_length: int) -> str:
    """RFC 6238のASCIIシークレットをBase32エンコードした文字列として返す。"""
    return base64.b32encode(_rfc6238_seed(byte_length)).decode("ascii")


#: RFC 6238 Appendix B「Test Values」表に基づく公式テストベクター。
#: (Unix時刻, ダイジェストアルゴリズム, シークレットのバイト長, 期待される8桁コード)
RFC6238_TEST_VECTORS: list[tuple[int, str, int, str]] = [
    (59, "sha1", 20, "94287082"),
    (59, "sha256", 32, "46119246"),
    (59, "sha512", 64, "90693936"),
    (1111111109, "sha1", 20, "07081804"),
    (1111111109, "sha256", 32, "68084774"),
    (1111111109, "sha512", 64, "25091201"),
    (1111111111, "sha1", 20, "14050471"),
    (1111111111, "sha256", 32, "67062674"),
    (1111111111, "sha512", 64, "99943326"),
    (1234567890, "sha1", 20, "89005924"),
    (1234567890, "sha256", 32, "91819424"),
    (1234567890, "sha512", 64, "93441116"),
    (2000000000, "sha1", 20, "69279037"),
    (2000000000, "sha256", 32, "90698825"),
    (2000000000, "sha512", 64, "38618901"),
    (20000000000, "sha1", 20, "65353130"),
    (20000000000, "sha256", 32, "77737706"),
    (20000000000, "sha512", 64, "47863826"),
]


class TestRfc6238OfficialTestVectors:
    """RFC 6238 Appendix Bの公式テストベクターによる検証。"""

    @pytest.mark.parametrize(
        ("for_time", "digest", "byte_length", "expected_code"), RFC6238_TEST_VECTORS
    )
    def test_generates_expected_code_for_official_vector(
        self, for_time: int, digest: str, byte_length: int, expected_code: str
    ) -> None:
        """規定の時刻・シークレット・アルゴリズムで正しい8桁コードが生成されることを確認する。"""
        secret = _rfc6238_secret(byte_length)
        code = generate_totp(
            secret, time_step=30, digits=8, digest=digest, for_time=for_time
        )
        assert code == expected_code


class TestGenerateTotp:
    """generate_totp の基本的な挙動に関するテスト。"""

    def test_default_digits_is_six(self) -> None:
        """既定の桁数が6桁であることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        code = generate_totp(secret, for_time=59)
        assert len(code) == 6
        assert code.isdigit()

    def test_code_is_deterministic_for_same_inputs(self) -> None:
        """同じ入力からは常に同じコードが得られる（決定的である）ことを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        first = generate_totp(secret, for_time=1111111111)
        second = generate_totp(secret, for_time=1111111111)
        assert first == second

    def test_different_time_steps_can_produce_different_codes(self) -> None:
        """異なる時間ステップ（カウンタ値）では異なるコードになり得ることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        code_at_59 = generate_totp(secret, for_time=59)
        code_at_1111111111 = generate_totp(secret, for_time=1111111111)
        assert code_at_59 != code_at_1111111111

    def test_same_time_step_window_produces_same_code(self) -> None:
        """同じ30秒ウィンドウ内であれば秒が異なっても同じコードになることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        code_at_start = generate_totp(secret, time_step=30, for_time=30)
        code_at_end = generate_totp(secret, time_step=30, for_time=59)
        assert code_at_start == code_at_end

    def test_custom_digits_changes_code_length(self) -> None:
        """digitsを指定すると、その桁数のコードが生成されることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        code = generate_totp(secret, digits=8, for_time=59)
        assert len(code) == 8

    def test_unsupported_digest_raises_value_error(self) -> None:
        """未対応のダイジェストアルゴリズムを指定するとValueErrorになることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        with pytest.raises(ValueError):
            generate_totp(secret, digest="md5", for_time=59)

    def test_non_positive_time_step_raises_value_error(self) -> None:
        """time_stepが0以下の場合にValueErrorになることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        with pytest.raises(ValueError):
            generate_totp(secret, time_step=0, for_time=59)

    def test_non_positive_digits_raises_value_error(self) -> None:
        """digitsが0以下の場合にValueErrorになることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        with pytest.raises(ValueError):
            generate_totp(secret, digits=0, for_time=59)


class TestSecretNormalization:
    """Base32シークレットの正規化に関するテスト。"""

    def test_lowercase_secret_is_normalized(self) -> None:
        """小文字のシークレットが大文字の場合と同じコードを生成することを確認する。"""
        secret_upper = base64.b32encode(b"12345678901234567890").decode("ascii")
        secret_lower = secret_upper.lower()
        assert generate_totp(secret_upper, for_time=59) == generate_totp(
            secret_lower, for_time=59
        )

    def test_secret_with_internal_and_surrounding_spaces_is_normalized(self) -> None:
        """内部・前後にスペースを含むシークレットが正規化後と同じコードを生成することを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        spaced_secret = f"  {secret[:4]} {secret[4:8]} {secret[8:]}  "
        assert generate_totp(spaced_secret, for_time=59) == generate_totp(
            secret, for_time=59
        )

    def test_secret_without_padding_is_accepted(self) -> None:
        """末尾の`=`パディングを除去したシークレットでも正しく処理されることを確認する。"""
        # 12バイト（5の倍数でない長さ）はBase32エンコード時にパディングが必要になる。
        secret = base64.b32encode(b"hello world!").decode("ascii")
        unpadded_secret = secret.rstrip("=")
        assert unpadded_secret != secret
        assert generate_totp(unpadded_secret, for_time=59) == generate_totp(
            secret, for_time=59
        )

    def test_validate_secret_accepts_valid_base32(self) -> None:
        """正しいBase32文字列に対してvalidate_secretが例外を送出しないことを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        validate_secret(secret)


class TestInvalidSecret:
    """不正なシークレットに関するテスト。"""

    def test_empty_secret_raises_invalid_secret_error(self) -> None:
        """空文字列のシークレットがInvalidSecretErrorになることを確認する。"""
        with pytest.raises(InvalidSecretError):
            validate_secret("")

    def test_whitespace_only_secret_raises_invalid_secret_error(self) -> None:
        """空白文字のみのシークレットがInvalidSecretErrorになることを確認する。"""
        with pytest.raises(InvalidSecretError):
            validate_secret("   ")

    @pytest.mark.parametrize("invalid_char", ["0", "1", "8", "9", "!", "_", "@"])
    def test_secret_with_non_base32_characters_raises_invalid_secret_error(
        self, invalid_char: str
    ) -> None:
        """Base32文字集合（A-Z, 2-7）に含まれない文字を含むとInvalidSecretErrorになることを確認する。"""
        with pytest.raises(InvalidSecretError):
            validate_secret(f"JBSWY3DPEHPK3PXP{invalid_char}")

    def test_generate_totp_with_invalid_secret_raises_invalid_secret_error(
        self,
    ) -> None:
        """generate_totpも不正なシークレットに対してInvalidSecretErrorを送出することを確認する。"""
        with pytest.raises(InvalidSecretError):
            generate_totp("not-valid-base32!!!", for_time=59)

    def test_secret_with_invalid_padding_count_raises_invalid_secret_error(
        self,
    ) -> None:
        """文字集合は正しいが、Base32として不正なパディング数を持つ文字列がInvalidSecretErrorになることを確認する。

        6文字のデータ+2個の`=`は、正規表現（A-Z2-7 + 末尾の`=`）は通過するが、
        RFC 4648上有効なパディングパターンではないためBase32デコードに失敗する。
        """
        with pytest.raises(InvalidSecretError):
            validate_secret("ABCDEF==")

    def test_negative_for_time_raises_value_error(self) -> None:
        """エポック以前の負の時刻を指定すると、負のカウンタとなりValueErrorになることを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        with pytest.raises(ValueError):
            generate_totp(secret, for_time=-1)

    def test_error_message_does_not_leak_secret_value(self) -> None:
        """例外メッセージに元のシークレット文字列が含まれないことを確認する（Zero Leakage Rule）。"""
        secret = "SUPER-SECRET-VALUE-1"
        with pytest.raises(InvalidSecretError) as excinfo:
            validate_secret(secret)
        assert secret not in str(excinfo.value)
        assert "SUPER-SECRET-VALUE" not in str(excinfo.value)


class TestRemainingSeconds:
    """remaining_seconds に関するテスト。"""

    def test_returns_full_window_right_after_boundary(self) -> None:
        """時間ステップの境界直後は、ほぼ満額の残り秒数になることを確認する。"""
        assert remaining_seconds(time_step=30, for_time=30) == 30

    def test_returns_one_second_just_before_boundary(self) -> None:
        """時間ステップの境界直前は、残り秒数が1になることを確認する。"""
        assert remaining_seconds(time_step=30, for_time=59) == 1

    @pytest.mark.parametrize("for_time", [0, 30, 60, 90, 1111111110])
    def test_returns_full_window_exactly_at_period_start(self, for_time: int) -> None:
        """t % time_step == 0（周期開始ジャスト）のとき、残り秒数がtime_stepと等しいことを確認する。"""
        assert for_time % 30 == 0
        assert remaining_seconds(time_step=30, for_time=for_time) == 30

    @pytest.mark.parametrize("for_time", [29, 59, 89, 119, 1111111109])
    def test_returns_one_second_just_before_period_switch(self, for_time: int) -> None:
        """t % time_step == time_step - 1（周期切り替わり直前）のとき、残り秒数が1になることを確認する。"""
        assert for_time % 30 == 29
        assert remaining_seconds(time_step=30, for_time=for_time) == 1

    def test_returns_half_window_at_midpoint(self) -> None:
        """時間ステップの中間地点では、残り半分の秒数になることを確認する。"""
        assert remaining_seconds(time_step=30, for_time=45) == 15

    def test_non_positive_time_step_raises_value_error(self) -> None:
        """time_stepが0以下の場合にValueErrorになることを確認する。"""
        with pytest.raises(ValueError):
            remaining_seconds(time_step=0, for_time=10)

    def test_uses_current_time_when_for_time_is_omitted(self) -> None:
        """for_time省略時は現在時刻を基準に0以上time_step以下の値を返すことを確認する。"""
        value = remaining_seconds(time_step=30)
        assert 0 <= value <= 30


class TestTotpGeneratorClass:
    """TotpGenerator クラス（オブジェクト指向インターフェース）に関するテスト。"""

    def test_generate_matches_module_level_function(self) -> None:
        """TotpGenerator.generateがgenerate_totp関数と同じ結果を返すことを確認する。"""
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        generator = TotpGenerator(digits=8, time_step=30, digest="sha1")
        assert generator.generate(secret, for_time=59) == generate_totp(
            secret, time_step=30, digits=8, digest="sha1", for_time=59
        )

    def test_remaining_seconds_matches_module_level_function(self) -> None:
        """TotpGenerator.remaining_secondsがremaining_seconds関数と同じ結果を返すことを確認する。"""
        generator = TotpGenerator(time_step=30)
        assert generator.remaining_seconds(for_time=45) == remaining_seconds(
            time_step=30, for_time=45
        )

    def test_validate_secret_raises_for_invalid_secret(self) -> None:
        """TotpGenerator.validate_secretが不正なシークレットでInvalidSecretErrorを送出することを確認する。"""
        generator = TotpGenerator()
        with pytest.raises(InvalidSecretError):
            generator.validate_secret("invalid-secret-!!!")

    def test_validate_secret_returns_normalized_string_for_valid_secret(self) -> None:
        """TotpGenerator.validate_secretが正常なシークレットに対して正規化文字列を返すことを確認する。"""
        generator = TotpGenerator()
        normalized = generator.validate_secret("  jbswy3dpehpk3pxp  ")
        assert normalized == "JBSWY3DPEHPK3PXP"

    def test_validate_secret_returned_string_is_directly_decodable(self) -> None:
        """validate_secretが返す正規化文字列が、そのままgenerate_totpへ渡しても同じ結果になることを確認する。"""
        generator = TotpGenerator()
        original_secret = "  jbswy3dpehpk3pxp  "
        normalized = generator.validate_secret(original_secret)
        assert generator.generate(normalized, for_time=59) == generator.generate(
            original_secret, for_time=59
        )

    def test_default_constructor_uses_documented_defaults(self) -> None:
        """既定コンストラクタがDESIGN.mdどおりの既定値（6桁, 30秒, SHA1）を持つことを確認する。"""
        generator = TotpGenerator()
        assert generator.digits == 6
        assert generator.time_step == 30
        assert generator.digest == "sha1"
