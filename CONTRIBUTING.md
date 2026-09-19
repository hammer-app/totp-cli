# vtotp 開発者ガイド

このドキュメントは開発環境の構築、テスト、静的解析の手順をまとめたものです。利用者向けの説明は [README.md](README.md) を参照してください。

## 開発環境のセットアップ

```bash
pip install -e ".[dev]"
```

## テストとカバレッジ

```bash
python -m pytest --cov=src/vtotp --cov-report=term-missing
```

## 静的解析

```bash
python -m flake8 src tests
python -m mypy src
python -m black --check src tests
```

`flake8` はリポジトリルートの [`.flake8`](.flake8) 設定を使用します。`max-line-length = 88` および `extend-ignore = E203, W503` を Black の設定と整合させてください。

フォーマットを修正する場合は次を実行します。

```bash
python -m black src tests
```

## 検証基準

- テストカバレッジ 100%
- `flake8`、`mypy`、`black --check` の警告・エラーゼロ
- Zero Leakage Rule、AES-256-GCM、Windows パス安全性などのセキュリティ要件を維持

## 参考リンク

- [README.md](README.md)
- [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- [docs/DESIGN.md](docs/DESIGN.md)
- [docs/BUILD.md](docs/BUILD.md)
