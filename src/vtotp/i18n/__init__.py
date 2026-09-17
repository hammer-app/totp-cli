"""vtotp.i18n パッケージの公開インターフェース。

型安全なメッセージカタログ（:class:`MsgKey` とその英日辞書）、および
表示言語解決ロジック（:class:`LanguageResolver`）を外部モジュールへ公開する。
"""

from __future__ import annotations

from vtotp.i18n.catalog import (
    DEFAULT_LANGUAGE,
    EN_CATALOG,
    JA_CATALOG,
    SUPPORTED_LANGUAGES,
    Catalog,
    MsgKey,
    get_catalog,
)
from vtotp.i18n.resolver import ENV_LANG_VARIABLE, LanguageResolver, detect_os_locale

__all__ = [
    "MsgKey",
    "Catalog",
    "EN_CATALOG",
    "JA_CATALOG",
    "SUPPORTED_LANGUAGES",
    "DEFAULT_LANGUAGE",
    "get_catalog",
    "LanguageResolver",
    "detect_os_locale",
    "ENV_LANG_VARIABLE",
]
