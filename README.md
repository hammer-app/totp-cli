[English](README.en.md) | 日本語

# vtotp

Windows 環境での実用性と堅牢性を重視して設計された、高セキュリティな CLI TOTP（時間基準ワンタイムパスワード）認証ツールです。

マスターキーと暗号化データの物理的分離、メモリ・ログへのシークレット完全非露出（Zero Leakage Rule）、そして Windows 特有のパス入力挙動に完全対応した設計で、端末固定かつポータブルな運用を重視しています。

---

## 主な特徴

- **強固な暗号化と鍵分離**: TOTP シークレットは AES-256-GCM で暗号化して保存されます。暗号化データと復号用のマスターキー（32バイト）は別々の場所に置けます。
- **Zero Leakage Rule（秘密情報の完全防衛）**:
  - 生成された 6 桁コードのみを `stdout`（標準出力）へ出力します。クリップボード連携や他コマンドへのパイプ渡し（`vtotp github | clip`）でも安全です。
  - 残り有効時間バーや進捗表示、案内・警告・エラーメッセージはすべて `stderr`（標準エラー出力）へ分離されます。
  - エラー発生時や通常出力時に、マスターキーや平文シークレットが画面・ログへ漏洩することは一切ありません。
- **日本語・英語の完全な多言語対応**: ヘルプ・プロンプト・エラーメッセージ等の全表示文言が日英で切り替え可能です（`-l` / `--lang`、環境変数、設定ファイルで解決）。
- **Windows フレンドリー**: エクスプローラーからコピーしたパスの引用符や空白を自動正規化し、不正な Windows パスによる Traceback の露出を防ぎます。
- **直感的な操作性**: `vtotp <service>` によるコード生成の省略形と、最大 3 世代までの鍵バックアップをサポートします。
- **耐タンパー性の高いネイティブバイナリ**: 配布用バイナリは Nuitka による C 言語トランスパイルで作成します。

---

## 動作環境

- Python 3.11 以上（ソースコード版利用時）
- Windows / macOS / Linux（配布バイナリは現時点で Windows x64 のみ）

---

## インストールと利用形態

vtotp は Standalone ZIP 版、Onefile EXE 版、ソースコード版（Python パッケージ）の 3 つの配布形態を提供しています。

### ① Standalone ZIP 版（推奨・高速）

[GitHub Releases](https://github.com/hammer-app/vtotp-cli/releases) から `vtotp-windows-x64.zip` をダウンロードし、任意のフォルダへ展開します。

```powershell
Expand-Archive vtotp-windows-x64.zip -DestinationPath C:\Tools\vtotp
C:\Tools\vtotp\vtotp.exe --version
```

### ② Onefile EXE 版（ポータブル・単体ファイル）

[Releases ページ](https://github.com/hammer-app/vtotp-cli/releases) から `vtotp.exe` をダウンロードし、任意のフォルダに配置して実行します。

```powershell
C:\Tools\vtotp\vtotp.exe --version
```

Onefile 版は実行時に一時展開が発生するため、Standalone 版より待機時間が増える可能性があります。

### ③ ソースコード版（Python / pip 経由）

```powershell
git clone https://github.com/hammer-app/vtotp-cli.git
cd vtotp-cli
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

インストール後、`vtotp` コマンドが使用可能になります。

---

## クイックスタート

### 1. 初期化 (`init`)

```powershell
vtotp init
vtotp init --key "C:\Users\<user>\OneDrive\個人用 Vault\master.key" -l ja
```

### 2. サービスの登録 (`add`)

```powershell
vtotp add github
vtotp add aws --secret JBSWY3DPEHPK3PXP --issuer Amazon
```

### 3. TOTP コードの生成 (`generate`、エイリアス: `get` / `-g`、省略形)

```powershell
vtotp github
vtotp generate github
vtotp get github
vtotp -g github
vtotp github | Set-Clipboard
```

### 4. サービス一覧の確認 (`list`、エイリアス: `ls`)

```powershell
vtotp list
vtotp ls
```

### 5. サービスの削除 (`remove`、エイリアス: `rm`)

```powershell
vtotp remove github
vtotp remove github --force
vtotp rm github -f
```

### 6. マスターキーのローテーション (`rekey`)

```powershell
vtotp rekey
```

---

## コマンド構文とオプション配置ルール

第一引数は予約サブコマンドまたはサービス名です。`SERVICE` を必要とするコマンドでは、オプションをサービス名の後方に指定します。

```powershell
vtotp get github -l ja
vtotp get github --key "PATH" -l ja
```

---

## 言語設定 (`-l` / `--lang`)

表示言語は、コマンドライン引数、`VTOTP_LANG`、`config.json`、OS ロケール、既定値 `en` の順に解決されます。

```powershell
vtotp list -l ja
vtotp github -l ja
$env:VTOTP_LANG = "ja"
```

```powershell
vtotp config
vtotp config -l ja
vtotp config set language en
```

---

## 設定と優先順位

マスターキーは `--key`、環境変数 `VTOTP_KEY_PATH`、`~/.vtotp/config.json` の順に解決されます。暗号化データは `--storage`、設定ファイル、設定ファイルと同じディレクトリの `vtotp-secrets.enc` の順に解決されます。

```powershell
vtotp config
```

---

## 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 成功 |
| 1 | 一般エラー |
| 2 | CLI 引数エラー |
| 3 | 鍵ファイルが存在しない・不正 |
| 4 | 暗号化データの破損・復号失敗 |
| 5 | 指定したサービスが未登録 |
| 6 | TOTP シークレットの形式が不正 |
| 7 | ユーザーによるキャンセル |

---

## 開発とビルド

- 開発環境の構築やテスト実行手順: [CONTRIBUTING.md](CONTRIBUTING.md)
- 配布バイナリのビルドや CI 仕様: [docs/BUILD.md](docs/BUILD.md)

テストカバレッジ 100% と静的解析の警告ゼロを信頼性の基準として維持しています。

---

## ライセンス

MIT License
