# 要件定義書: Custom CLI TOTP Authenticator (`totp-cli`)

## 1. 概要 (Overview)
特定端末および指定復号鍵が存在する場合のみ実行可能な、**「端末固定（クライアント認証）」および「ポータブル運用」を目的としたマルチプラットフォーム対応CLI型TOTP生成ツール**。

暗号化したTOTPシークレット群（JSON）と復号鍵（AES-256）を分離管理し、実行時にメモリ上で復号してワンタイムパスワードを出力する。

---

## 2. 目的・背景 (Background & Objectives)
* **目的:** 外部デバイスに依存せず、特定デバイス・特定鍵アクセス環境でのみ機能するクライアント認証環境の構築。
* **背景:**
  * パスワードマネージャー依存を避け、端末上のTerminal/CLIで高速に2FAコードを利用・取得したい。
  * 鍵と暗号化ファイルを移動・配置することで、Windows Personal Vault、Linux、macOS等の異なるOS・環境間でも安全に同一設定を引き継ぎたい。

---

## 3. 機能要件 (Functional Requirements)

### 3.1 核心機能
1. **TOTPコード生成・表示 (`generate` / `get` / `-g`)**
   * サービス名を受け取り、対応するTOTPコードを出力する。
   * **基本形:** `totp-cli generate <service>` / `totp-cli get <service>` / `totp-cli -g <service>`
   * **省略形:** `totp-cli <service>`
     * 第一引数が予約済みサブコマンドと一致しない場合は自動的に `generate` として処理する。
     * サブコマンドと同名のサービス名（例: `init`）を呼び出す場合は明示的に `get` / `generate` を付与する。

2. **鍵パスの動的指定・ポータビリティ (`-k` / `--key`)**
   * 復号鍵（`master.key`）の保存先は設定ファイル（`config.json`）、環境変数（`TOTP_KEY_PATH`）、または実行時オプション（`-k` / `--key`）で切り替え可能とする。

3. **複数サービス（マルチアカウント）管理**
   * 複数のTOTPシークレットを1つの暗号化JSONファイルで保持・管理する。

### 3.2 ライフサイクル・データ管理機能
4. **初期化機能 (`init`)**
   * 新規の復号鍵（AES-256）を生成・保存し、暗号化データファイル（空のJSON構造）とデフォルト設定を作成する。
5. **鍵の更新・再暗号化機能 (`rekey`)**
   * 新しい復号鍵を再生成し、既存の暗号化データを旧鍵で復号した上で**即座に新鍵で再暗号化**して保存する。
6. **登録一覧表示 (`list` / `ls`)**
   * 登録済みのサービス識別子（Key名）のみをリスト表示する（シークレット自体は非表示）。
7. **登録データ追加・更新 (`add`)**
   * シークレット追加時、`-s` / `--secret` オプションで渡すか、未指定時は対話形式で安全に入力させる。
8. **登録データ削除 (`remove` / `rm`)**
   * 指定したサービス名の登録情報を削除する（確認ダイアログまたは `-f` / `--force` 対応）。

---

## 4. 非機能要件 (Non-Functional Requirements)

### 4.1 セキュリティ・プライバシー
* **暗号化規格:** AES-256（`cryptography.fernet` 等）を使用。
* **メモリ保護:** 復号されたシークレットやJSONデータはファイル保存せず、処理完了時にメモリから破棄する。
* **ポータビリティ:** Python標準/一般的なライブラリのみで構成し、Windows / Linux / macOS 上で同一に動作させる。

---

## 5. CLI設計・コマンド体系

```bash
# 1. 初回初期化
$ totp-cli init -k "C:/Users/.../Personal Vault/master.key"

# 2. サービス追加 (-s でシークレット指定)
$ totp-cli add github -s "JBSWY3DPEHPK3PXP"

# 3. コード取得 (省略形・明示形)
$ totp-cli github
123456
$ totp-cli generate github -k "E:/USB/master.key"
987654

# 4. 一覧表示 (ls エイリアス)
$ totp-cli ls

# 5. 鍵更新
$ totp-cli rekey -k "E:/USB/new_master.key"

```

---

## 6. 各AIツールへの役割分担

* **GitHub Copilot (設計・構造化):**
  - `REQUIREMENTS.md` を読み込ませ、CLIアーキテクチャ（`argparse` / `click` / `typer` 等）、構文解析のフォールバック処理、クラス設計を出力させる。


* **Claude Code (実装・テスト):**
  - 設計書をもとに実装モジュール、ユニットテスト（`pytest`）、エラーハンドリング（鍵不在・破損時の安全性確保）を構築させる。
