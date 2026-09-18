"""登録済みTOTPサービスの管理を担う ServiceRegistry を定義するモジュール。

DESIGN.md 10章「ServiceRegistry」に基づき、サービスの登録・取得・一覧・
削除のロジックを提供する。サービス名は大文字小文字を区別せず、常に
正規化（前後空白除去・小文字化）された形で保持・検索される。各メソッド
はレコード集合を不変（イミュータブル）として扱い、変更後の新しい辞書を
返す（呼び出し元から渡された辞書自体は変更しない）。
"""

from __future__ import annotations

from vtotp.domain.exceptions import ServiceNotFoundError, TotpCliError
from vtotp.domain.models import SecretRecord
from vtotp.i18n.catalog import MsgKey


class ServiceRegistry:
    """サービス名と :class:`SecretRecord` の対応関係を管理するクラス。

    シークレットの値そのものはこのクラスの関心事ではなく、あくまで
    サービス名をキーとしたレコード集合の追加・取得・一覧・削除のみを
    扱う。
    """

    def add(
        self,
        records: dict[str, SecretRecord],
        record: SecretRecord,
    ) -> dict[str, SecretRecord]:
        """新しいサービスをレコード集合へ追加する。

        サービス名は正規化（前後空白除去・小文字化）したうえで一意性を
        判定し、既に同名のサービスが登録済みの場合は重複登録として
        :class:`TotpCliError` を送出する（重複登録防止）。
        """
        normalized_name = self._normalize_service_name(record.service_name)
        if not normalized_name:
            raise TotpCliError(MsgKey.SERVICE_NAME_EMPTY)
        if normalized_name in records:
            raise TotpCliError(
                MsgKey.SERVICE_ALREADY_REGISTERED,
                context={"service": record.service_name},
            )

        updated = dict(records)
        updated[normalized_name] = SecretRecord(
            service_name=normalized_name,
            secret=record.secret,
            issuer=record.issuer,
        )
        return updated

    def get(
        self,
        records: dict[str, SecretRecord],
        service_name: str,
    ) -> SecretRecord:
        """指定したサービスのレコードを取得する。

        存在しないサービスが指定された場合は :class:`ServiceNotFoundError`
        を送出する。
        """
        normalized_name = self._normalize_service_name(service_name)
        try:
            return records[normalized_name]
        except KeyError as exc:
            raise ServiceNotFoundError(
                MsgKey.SERVICE_NOT_FOUND, context={"service": service_name}
            ) from exc

    def list_names(self, records: dict[str, SecretRecord]) -> list[str]:
        """登録済みのサービス名のみを昇順で返す。シークレットは返さない。"""
        return sorted(records.keys())

    def remove(
        self,
        records: dict[str, SecretRecord],
        service_name: str,
    ) -> dict[str, SecretRecord]:
        """指定したサービスのレコードを削除した新しいレコード集合を返す。

        存在しないサービスが指定された場合は :class:`ServiceNotFoundError`
        を送出する。
        """
        normalized_name = self._normalize_service_name(service_name)
        if normalized_name not in records:
            raise ServiceNotFoundError(
                MsgKey.SERVICE_NOT_FOUND, context={"service": service_name}
            )

        updated = dict(records)
        del updated[normalized_name]
        return updated

    def _normalize_service_name(self, service_name: str) -> str:
        """サービス名の前後空白を除去し、小文字化して正規化する（内部用）。"""
        return service_name.strip().lower()
