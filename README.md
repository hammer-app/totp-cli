# totp-cli

Windows 環境での実用性と堅牢性を重視して設計された、高セキュリティな CLI TOTP（時間基準ワンタイムパスワード）認証ツールです。

マスターキーと暗号化データの物理的分離、メモリ・ログへのシークレット完全非露出（Zero Leakage Rule）、そして Windows 特有のパス入力挙動に完全対応しています。

---

## 主な特徴

- **強固な暗号化と鍵分離**: TOTP シークレットは AES-256-GCM で暗号化して保存されます。暗号化データと復号用のマスターキー（32バイト）は別々の安全な場所（外部メディア、OneDrive Vault 等）に分離管理できます。
- **Zero Leakage Rule（秘密情報の完全防衛）**:
  - 生成された 6 桁コードのみを `stdout`（標準出力）へ出力します。クリップボード連携や他コマンドへのパイプ渡し（`totp github | clip`）でも安全です。
  - 残り有効時間バーや進捗表示はすべて `stderr`（標準エラー出力）へ分離されます。
  - エラー発生時や通常出力時に、マスターキーや平文シークレットが画面・ログへ漏洩することは一切ありません。
- **Windows フレンドリー**:
  - エクスプローラーの「パスのコピー」等で混入する引用符（`"` や `'`）や全角空白混じりのパスを自動正規化。
  - Windows 特有の不正文字による `[WinError 123]` や未処理例外（Traceback）の露出を完全に防ぎます。
- **直感的な操作性**:
  - 頻繁に使うコード生成はサブコマンドを省略可能（`totp <service>` のみで即座に発行）。
  - 鍵の安全な世代交代（最大 3 世代までの自動バックアップ）をサポート。

---

## 動作環境

- Python 3.11 以上
- Windows / macOS / Linux

---

## インストール

仮想環境を作成し、編集可能（editable）モードまたは通常モードでインストールします。

```powershell
# リポジトリのクローン
git clone https://github.com/hammer-app/totp-cli.git
cd totp-cli

# 仮想環境の作成と有効化
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# インストール（開発依存パッケージを含む場合: ".[dev]"）
pip install -e .

```

インストール後、`totp` コマンドが使用可能になります。

---

## クイックスタート

### 1. 初期化 (`init`)

マスターキーを作成し、暗号化ストレージを初期化します。

```powershell
# 対話プロンプトで保存先パスを入力する場合
totp init

```

対話プロンプトが表示されたら、鍵の保存先パス（例: `"C:\Users\<user>\OneDrive\個人用 Vault\master.key"`）を指定します。引用符で囲んだまま貼り付けても自動的に除去されます。

```powershell
# 保存先パスを引数で直接指定する場合（-k / --key、対話プロンプトなし）
totp init --key "C:\Users\<user>\OneDrive\個人用 Vault\master.key"
totp init -k "D:\USB\master.key"

```

### 2. サービスの登録 (`add`)

Base32 形式の TOTP シークレットを登録します。

```powershell
# 対話プロンプトで安全に入力する場合（推奨: ターミナル履歴に残りません）
totp add github

# 引数で直接指定する場合
totp add aws --secret JBSWY3DPEHPK3PXP --issuer Amazon

```

### 3. TOTP コードの生成 (`generate`、エイリアス: `get` / `-g`、省略形)

サービス名を渡すだけで即座に 6 桁コードを取得できます。`generate` には `get` および `-g` というエイリアスがあります。

```powershell
# サブコマンド省略形（日常利用に最適。サービス名のみでgenerate扱いになる）
totp github

# 明示的なサブコマンド指定
totp generate github

# エイリアス（generateと完全に同じ動作）
totp get github
totp -g github

# クリップボードへ直接コピー（PowerShell）
totp github | Set-Clipboard

```

### 4. サービス一覧の確認 (`list`、エイリアス: `ls`)

登録されているサービス名と発行者（Issuer）を表示します（シークレットは表示されません）。`ls` は `list` のエイリアスです。

```powershell
totp list
# ls は list のエイリアス
totp ls

```

### 5. サービスの削除 (`remove`、エイリアス: `rm`)

不要になったサービスを安全に削除します。`rm` は `remove` のエイリアスです。

```powershell
# 確認プロンプトあり
totp remove github

# 確認をスキップして即時削除
totp remove github --force

# rm は remove のエイリアス（動作は同じ）
totp rm github --force

```

### 6. マスターキーのローテーション (`rekey`)

ストレージを再暗号化し、新しいマスターキーを発行します（旧鍵は `<key_path>.1` として自動退避されます）。

```powershell
totp rekey

```

---

## 設定と優先順位

マスターキーの参照先は以下の優先順位で自動解決されます。

1. コマンドライン引数（`-k PATH` または `--key PATH`）
2. 環境変数 `TOTP_KEY_PATH`
3. 初期化時に保存された設定ファイル（`~/.totp-cli/config.json`）

暗号化データファイルの参照先は `--storage PATH` で一時的に上書きできます（`config.json` には保存されません）。指定が無い場合は `config.json` の `storage_path`、それも無い場合は `config.json` と同じディレクトリの `totp-secrets.enc` が既定値として使用されます。

現在の設定状況は以下のコマンドで確認できます。

```powershell
totp config

```

---

## 終了コード

スクリプトから呼び出す際は、以下の終了コードで結果を判定できます。

| コード | 意味 |
| --- | --- |
| 0 | 成功 |
| 1 | 一般エラー（ファイル操作の失敗等） |
| 2 | CLI 引数エラー |
| 3 | 鍵ファイルが存在しない・不正 |
| 4 | 暗号化データの破損・復号失敗 |
| 5 | 指定したサービスが未登録 |
| 6 | TOTP シークレットの形式が不正 |
| 7 | ユーザーによるキャンセル |

---

## 開発とテスト

本プロジェクトはテスト駆動開発（TDD）に基づき、全テストの通過と 100% カバレッジ、厳格な静的解析を維持しています。

```powershell
# テスト用依存パッケージを含めて編集可能モードでインストール
pip install -e ".[dev]"

# 全単体・統合テストの実行（カバレッジ計測）
python -m pytest --cov=totp_cli --cov-report=term-missing

# 静的解析
python -m flake8 src tests
python -m mypy src --strict
python -m black --check src tests

```

現時点での検証実績: **404 passed, 1 skipped**（Windows では `os.chmod` による権限剥奪を検証する1件のみ既定でスキップ）、カバレッジ **100%**。`flake8` / `mypy --strict` / `black --check` はいずれも警告ゼロです。

---

## ライセンス

MIT License
