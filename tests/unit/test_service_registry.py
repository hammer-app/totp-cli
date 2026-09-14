"""totp_cli.core.service_registry.ServiceRegistry の単体テスト。"""

from __future__ import annotations

import pytest

from totp_cli.core.service_registry import ServiceRegistry
from totp_cli.domain.exceptions import ServiceNotFoundError
from totp_cli.domain.models import SecretRecord


@pytest.fixture
def registry() -> ServiceRegistry:
    """テスト対象のServiceRegistryインスタンスを返す。"""
    return ServiceRegistry()


@pytest.fixture
def github_record() -> SecretRecord:
    """テスト用のGitHubサービスレコードを返す。"""
    return SecretRecord(
        service_name="github", secret="JBSWY3DPEHPK3PXP", issuer="GitHub"
    )


class TestAdd:
    """add に関するテスト。"""

    def test_adds_new_service_to_empty_registry(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """空のレコード集合に新しいサービスを追加できることを確認する。"""
        updated = registry.add({}, github_record)
        assert updated["github"] == github_record

    def test_does_not_mutate_the_original_dict(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """addが呼び出し元の辞書自体を変更しないことを確認する。"""
        original: dict[str, SecretRecord] = {}
        registry.add(original, github_record)
        assert original == {}

    def test_service_name_is_normalized_to_lowercase(
        self, registry: ServiceRegistry
    ) -> None:
        """サービス名が小文字へ正規化されて保存されることを確認する。"""
        record = SecretRecord(service_name="GitHub", secret="JBSWY3DPEHPK3PXP")
        updated = registry.add({}, record)
        assert "github" in updated
        assert updated["github"].service_name == "github"

    def test_service_name_surrounding_whitespace_is_stripped(
        self, registry: ServiceRegistry
    ) -> None:
        """サービス名の前後の空白が除去されて保存されることを確認する。"""
        record = SecretRecord(service_name="  github  ", secret="JBSWY3DPEHPK3PXP")
        updated = registry.add({}, record)
        assert list(updated.keys()) == ["github"]

    def test_duplicate_service_name_raises_value_error(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """同名のサービスを再度追加しようとするとValueErrorが送出されることを確認する（重複登録防止）。"""
        existing = registry.add({}, github_record)
        with pytest.raises(ValueError):
            registry.add(existing, github_record)

    def test_duplicate_detection_is_case_insensitive(
        self, registry: ServiceRegistry
    ) -> None:
        """大文字小文字が異なるだけの同名サービスも重複として検出されることを確認する。"""
        existing = registry.add(
            {}, SecretRecord(service_name="GitHub", secret="AAAAAAAA")
        )
        with pytest.raises(ValueError):
            registry.add(
                existing, SecretRecord(service_name="github", secret="BBBBBBBB")
            )

    def test_empty_service_name_raises_value_error(
        self, registry: ServiceRegistry
    ) -> None:
        """空文字列（または空白のみ）のサービス名がValueErrorになることを確認する。"""
        with pytest.raises(ValueError):
            registry.add(
                {}, SecretRecord(service_name="   ", secret="JBSWY3DPEHPK3PXP")
            )

    def test_can_add_multiple_distinct_services(
        self, registry: ServiceRegistry
    ) -> None:
        """異なる複数のサービスを追加できることを確認する。"""
        updated = registry.add(
            {}, SecretRecord(service_name="github", secret="AAAAAAAA")
        )
        updated = registry.add(
            updated, SecretRecord(service_name="aws", secret="BBBBBBBB")
        )
        assert set(updated.keys()) == {"github", "aws"}


class TestGet:
    """get に関するテスト。"""

    def test_returns_the_matching_record(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """登録済みサービスのレコードが取得できることを確認する。"""
        records = registry.add({}, github_record)
        assert registry.get(records, "github") == github_record

    def test_lookup_is_case_insensitive(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """大文字小文字を区別せずにサービスを取得できることを確認する。"""
        records = registry.add({}, github_record)
        assert registry.get(records, "GitHub") == github_record
        assert registry.get(records, "GITHUB") == github_record

    def test_lookup_ignores_surrounding_whitespace(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """前後に空白を含むサービス名でも取得できることを確認する。"""
        records = registry.add({}, github_record)
        assert registry.get(records, "  github  ") == github_record

    def test_missing_service_raises_service_not_found_error(
        self, registry: ServiceRegistry
    ) -> None:
        """存在しないサービスを指定するとServiceNotFoundErrorが送出されることを確認する。"""
        with pytest.raises(ServiceNotFoundError):
            registry.get({}, "unknown-service")

    def test_whitespace_only_service_name_raises_service_not_found_error(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """空白のみのサービス名を指定した場合にServiceNotFoundErrorが送出されることを確認する。"""
        records = registry.add({}, github_record)
        with pytest.raises(ServiceNotFoundError):
            registry.get(records, "   ")

    def test_registered_with_surrounding_whitespace_is_retrievable_by_trimmed_name(
        self, registry: ServiceRegistry
    ) -> None:
        """前後に空白を含む名前で登録したサービスが、トリムされた名前で取得できることを確認する。"""
        records = registry.add(
            {}, SecretRecord(service_name="  github  ", secret="JBSWY3DPEHPK3PXP")
        )
        record = registry.get(records, "github")
        assert record.service_name == "github"
        assert record.secret == "JBSWY3DPEHPK3PXP"


class TestListNames:
    """list_names に関するテスト。"""

    def test_returns_empty_list_for_empty_registry(
        self, registry: ServiceRegistry
    ) -> None:
        """空のレコード集合に対しては空リストを返すことを確認する。"""
        assert registry.list_names({}) == []

    def test_returns_all_registered_service_names_sorted(
        self, registry: ServiceRegistry
    ) -> None:
        """登録済みの全サービス名を昇順で返すことを確認する。"""
        records = registry.add(
            {}, SecretRecord(service_name="github", secret="AAAAAAAA")
        )
        records = registry.add(
            records, SecretRecord(service_name="aws", secret="BBBBBBBB")
        )
        records = registry.add(
            records, SecretRecord(service_name="slack", secret="CCCCCCCC")
        )
        assert registry.list_names(records) == ["aws", "github", "slack"]

    def test_does_not_expose_secrets(self, registry: ServiceRegistry) -> None:
        """一覧にシークレットの値が含まれないことを確認する（Zero Leakage Rule）。"""
        records = registry.add(
            {}, SecretRecord(service_name="github", secret="JBSWY3DPEHPK3PXP")
        )
        names = registry.list_names(records)
        assert names == ["github"]
        assert all("JBSWY3DPEHPK3PXP" not in name for name in names)


class TestRemove:
    """remove に関するテスト。"""

    def test_removes_the_specified_service(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """指定したサービスが削除されることを確認する。"""
        records = registry.add({}, github_record)
        updated = registry.remove(records, "github")
        assert "github" not in updated

    def test_does_not_mutate_the_original_dict(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """removeが呼び出し元の辞書自体を変更しないことを確認する。"""
        records = registry.add({}, github_record)
        registry.remove(records, "github")
        assert "github" in records

    def test_removal_is_case_insensitive(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """大文字小文字を区別せずに削除できることを確認する。"""
        records = registry.add({}, github_record)
        updated = registry.remove(records, "GitHub")
        assert updated == {}

    def test_does_not_affect_other_services(self, registry: ServiceRegistry) -> None:
        """他のサービスのレコードが影響を受けないことを確認する。"""
        records = registry.add(
            {}, SecretRecord(service_name="github", secret="AAAAAAAA")
        )
        records = registry.add(
            records, SecretRecord(service_name="aws", secret="BBBBBBBB")
        )
        updated = registry.remove(records, "github")
        assert set(updated.keys()) == {"aws"}

    def test_missing_service_raises_service_not_found_error(
        self, registry: ServiceRegistry
    ) -> None:
        """存在しないサービスを削除しようとするとServiceNotFoundErrorが送出されることを確認する。"""
        with pytest.raises(ServiceNotFoundError):
            registry.remove({}, "unknown-service")

    def test_whitespace_only_service_name_raises_service_not_found_error(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """空白のみのサービス名を指定した場合にServiceNotFoundErrorが送出されることを確認する。"""
        records = registry.add({}, github_record)
        with pytest.raises(ServiceNotFoundError):
            registry.remove(records, "   ")

    def test_registered_with_surrounding_whitespace_is_removable_by_trimmed_name(
        self, registry: ServiceRegistry
    ) -> None:
        """前後に空白を含む名前で登録したサービスが、トリムされた名前で削除できることを確認する。"""
        records = registry.add(
            {}, SecretRecord(service_name="  github  ", secret="JBSWY3DPEHPK3PXP")
        )
        updated = registry.remove(records, "github")
        assert updated == {}


class TestZeroLeakageRule:
    """Zero Leakage Rule（シークレットの非漏洩）に関するテスト。"""

    def test_service_not_found_error_message_does_not_leak_other_secrets(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """ServiceNotFoundErrorのメッセージに、登録済みの他サービスのシークレットが含まれないことを確認する。"""
        records = registry.add({}, github_record)
        with pytest.raises(ServiceNotFoundError) as excinfo:
            registry.get(records, "unknown-service")
        assert github_record.secret not in str(excinfo.value)

    def test_duplicate_error_message_does_not_leak_secret(
        self, registry: ServiceRegistry, github_record: SecretRecord
    ) -> None:
        """重複登録エラーのメッセージにシークレットの値が含まれないことを確認する。"""
        records = registry.add({}, github_record)
        with pytest.raises(ValueError) as excinfo:
            registry.add(records, github_record)
        assert github_record.secret not in str(excinfo.value)
