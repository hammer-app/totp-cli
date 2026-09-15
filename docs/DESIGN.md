# Custom CLI TOTP Authenticator 詳細アーキテクチャ設計書

## 1. 設計方針

- CLI名: `vtotp`
- 対応OS: Windows / Linux / macOS
- Python: 3.11以上を推奨
- 暗号化方式: AES-256-GCM
- TOTP: RFC 6238準拠
- 秘密情報は標準出力、ログ、平文ファイルへ出力しない
- 鍵ファイルと暗号化データファイルは分離する
- TOTPシークレットは処理中のみメモリ上で扱う

> `cryptography.fernet` は内部でAESを使用するが、AES-256-GCMを明示的に要求する場合は `AESGCM` を使用する。

## 2. 推奨プロジェクト構造

```text
vtotp/
├── pyproject.toml
├── README.md
├── src/
│   └── vtotp/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── handler.py
│       │   ├── parser.py
│       │   ├── commands.py
│       │   └── output.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── key_manager.py
│       │   ├── secure_storage.py
│       │   ├── totp_generator.py
│       │   ├── config_manager.py
│       │   └── service_registry.py
│       ├── domain/
│       │   ├── __init__.py
│       │   ├── models.py
│       │   └── exceptions.py
│       └── infrastructure/
│           ├── __init__.py
│           ├── file_system.py
│           └── platform_paths.py
├── tests/
│   ├── unit/
│   │   ├── test_key_manager.py
│   │   ├── test_secure_storage.py
│   │   ├── test_totp_generator.py
│   │   └── test_cli_handler.py
│   └── integration/
│       └── test_cli_commands.py
└── config/
    └── config.example.json
```

### 実行時データの配置例

```text
~/.totp-cli/
├── config.json
└── totp-secrets.enc
```

`config.json` は鍵ファイルの内容を保存せず、鍵ファイルのパスだけを指定する。鍵ファイルはツールの内部データとして保持せず、`config.json` の `key_path` に指定された外部パスへ保存する。通常の実行では、指定されたパスに鍵ファイルが存在しない場合、ツールは実行を中止する。

```json
{
    "key_path": "C:/Users/example/Personal Vault/master.key",
    "storage_path": "totp-secrets.enc"
}
```

### 鍵ファイルの管理方針

```text
- 鍵ファイルの内容はconfig.json、ツール内の内部データ、プロジェクト管理対象ファイルへ保存しない
- config.jsonには鍵の内容ではなく、鍵ファイルのパスだけを保存する
- 通常の実行ではconfig.jsonのkey_pathを必須とし、指定先に鍵が存在することを前提にする
- key_pathのファイルが存在しない、読み込めない、または32バイトでない場合はエラー終了する
- 通常の実行でTOTP_KEY_PATHや--keyを使用する場合は、指定先に既存の鍵ファイルがあることを必須とする
- initは新しい32バイト鍵を生成し、指定された外部パスへ保存した上で、そのパスをconfig.jsonへ保存する
- rekeyはconfig.jsonのkey_pathで指定された鍵ファイルを更新し、既存データを新鍵で再暗号化する
- initで--keyが指定されない場合は、対話入力で鍵ファイルの出力先を必ず指定させる
- initとrekeyで生成する鍵の保存先は、ツール内の暗黙の既定パスにしない
- config.jsonを書き換えるのはinitだけとし、initでも永続化対象はkey_pathだけとする
- --keyと--storageは、config.jsonへ保存しない一時的な実行時指定とする
- rekeyでは、更新前の鍵ファイルを世代番号付きで退避し、暗号化済みシークレットデータのローテーション保存は行わない
- 鍵ファイルの保持上限は3世代とし、`<key_path>.1` から `<key_path>.3` までを保持する
- 保持上限到達時は専用オプションを使用せず、警告への対話応答で続行または中止を決定する
```

### 復号後の論理データ構造

```json
{
  "version": 1,
  "services": {
    "github": {
      "secret": "JBSWY3DPEHPK3PXP",
      "issuer": "GitHub"
    }
  }
}
```

### 暗号化ファイルの構造

JSON全体を暗号化し、ファイルにはメタデータと暗号文だけを保存する。

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "nonce": "<base64>",
  "ciphertext": "<base64>"
}
```

## 3. CLIライブラリの選定

### 推奨: `argparse`

```text
- Python標準ライブラリで追加依存が不要
- Windows / Linux / macOSで動作差が少ない
- -g、-k、--secret、--forceなどを明確に定義できる
- サブコマンドとエイリアスを細かく制御できる
- vtotp <service> の独自フォールバック処理を実装しやすい
- CLIの挙動を予測しやすい
```

| ライブラリ | 長所 | 短所 | 評価 |
| --- | --- | --- | --- |
| `argparse` | 標準搭載、依存が少ない、細かい制御が可能 | 定義量がやや多い | 推奨 |
| `click` | サブコマンドや入力処理が書きやすい | 外部依存が増える | 採用候補 |
| `typer` | 型ヒントを利用でき、記述量が少ない | Click依存、抽象化が強い | 将来候補 |

ポータビリティと予測可能性を重視し、初期実装では `argparse` を採用する。

## 4. 主要モジュールの責務

```text
CliHandler
    CLI入力の前処理、予約コマンド判定、引数解析、エラー表示

KeyManager
    鍵の生成、読み込み、存在確認、鍵パス解決、権限確認

SecureStorage
    暗号化ファイルの読み込み、復号、暗号化、atomic保存、再暗号化

TotpGenerator
    Base32シークレットの検証、TOTPコード生成

ConfigManager
    config.jsonの読み込み、CLI・環境変数・既定値の統合、解決済み設定の提供

ServiceRegistry
    サービスの追加、更新、削除、一覧取得

CommandService
    init、generate、add、remove、list、rekey、configのユースケース実行
```

## 5. ドメインモデルと例外

```python
class SecretRecord:
    service_name: str
    secret: str
    issuer: str | None


class AppConfig:
    key_path: Path
    storage_path: Path


class EncryptedPayload:
    version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes
```

```python
class TotpCliError(Exception):
    """アプリケーション共通例外"""


class KeyNotFoundError(TotpCliError):
    pass


class InvalidKeyError(TotpCliError):
    pass


class StorageCorruptedError(TotpCliError):
    pass


class ServiceNotFoundError(TotpCliError):
    pass


class InvalidSecretError(TotpCliError):
    pass


class CommandParseError(TotpCliError):
    pass
```

## 6. KeyManager

### KeyManagerの責務

- AES-256用の32バイト鍵を生成する
- 鍵ファイルを読み込む
- 鍵サイズと形式を検証する
- CLI、環境変数、設定ファイルから鍵パスを解決する
- 通常の読み込み処理では、外部にある鍵ファイルの存在、形式、読み取り可否を検証する
- initとrekeyでは、指定された外部パスへ新規鍵を生成・保存する

### KeyManagerのインターフェース定義

```python
class KeyManager:
    def __init__(
        self,
        file_system: FileSystem,
        path_resolver: PathResolver,
    ) -> None:
        ...

    def generate_key(self) -> bytes:
        """暗号学的に安全な32バイト鍵を生成する"""
        ...

    def create_key_file(self, path: Path, key: bytes | None = None) -> None:
        """鍵を生成または受け取り、指定された外部パスへ保存する"""
        ...

    def rotate_key_file(self, path: Path, new_key: bytes) -> Path:
        """
        既存鍵を世代番号付きファイルへ繰り上げ、最古の鍵を必要に応じて削除し、
        新鍵をpathへ保存する。
        上限到達時の削除は、呼び出し元の対話確認後に実行する。
        """
        ...

    def rotated_key_paths(self, path: Path, max_generations: int = 3) -> list[Path]:
        """path.1からpath.Nまでのローテーション対象パスを返す"""
        ...

    def check_existing_key(self, path: Path) -> bool:
        """指定パスに既存の鍵ファイルがあるか確認する"""
        ...

    def verify_key_file(self, path: Path) -> None:
        """外部指定された既存の鍵ファイルを検証する"""
        ...

    def load_key(self, path: Path) -> bytes:
        """鍵を読み込み、32バイトであることを検証する"""
        ...

    def resolve_key_path(
        self,
        cli_path: Path | None,
        config_path: Path | None,
        environment_path: Path | None,
    ) -> Path:
        """
        優先順位:
        1. CLIオプション --key
        2. TOTP_KEY_PATH
        3. config.json
        4. パス未指定としてエラー
        """
        ...

    def validate_key_file(self, path: Path) -> None:
        """存在、通常ファイル、サイズ、読み取り可否を検証する"""
        ...
```

### 設計上の注意

```text
    - 通常の読み込み処理では、指定された外部パスに既存の鍵ファイルがあることを必須にする
    - initでは、指定された外部パスへ新規鍵を生成・保存する
    - rekeyでは、既存鍵をpath.1へ退避してから同じpathへ新鍵を保存する
    - WindowsではACL、Unix系では0600相当の権限を検証する
- 鍵の内容をエラーメッセージに含めない
```

## 7. SecureStorage

### SecureStorageの責務

- 暗号化JSONの読み込みと復号
- JSONデータの暗号化
- 一時ファイルを利用したatomic保存
- 再暗号化
- 暗号文の形式・バージョン検証

### SecureStorageのインターフェース定義

```python
class SecureStorage:
    def __init__(
        self,
        file_system: FileSystem,
        serializer: JsonSerializer,
    ) -> None:
        ...

    def initialize(self, path: Path, key: bytes) -> None:
        """空のサービスデータを暗号化して新規作成する"""
        ...

    def load(
        self,
        path: Path,
        key: bytes,
    ) -> dict[str, SecretRecord]:
        """暗号化ファイルを復号してサービス情報を返す"""
        ...

    def save(
        self,
        path: Path,
        key: bytes,
        records: dict[str, SecretRecord],
    ) -> None:
        """サービス情報を暗号化し、atomicに保存する"""
        ...

    def prepare_rekey(
        self,
        path: Path,
        old_key: bytes,
        new_key: bytes,
    ) -> Path:
        """新鍵で再暗号化した一時ファイルを作成し、検証済みパスを返す"""
        ...

    def commit_rekey(self, path: Path, prepared_path: Path) -> None:
        """検証済みの再暗号化データをatomicに正式ファイルへ置き換える"""
        ...

    def encrypt(
        self,
        payload: bytes,
        key: bytes,
    ) -> EncryptedPayload:
        ...

    def decrypt(
        self,
        encrypted_payload: EncryptedPayload,
        key: bytes,
    ) -> bytes:
        ...
```

### 保存処理の擬似フロー

```text
1. サービス情報をJSONへシリアライズ
2. 32バイト鍵をAES-256-GCMへ渡す
3. 暗号学的に安全なnonceを生成
4. JSONを暗号化
5. メタデータと暗号文を一時ファイルへ書き込む
6. ファイル内容を検証
7. atomic renameで正式ファイルへ置き換える
8. 一時ファイルを削除する
```

### セキュリティ要件

```text
- GCMの認証タグ検証に失敗した場合は復号を中止する
- 破損データを空データとして扱わない
- 復号失敗時に別の鍵で再試行しない
- 保存途中のプロセス終了で既存ファイルを破壊しない
- 復号済みJSONを平文ファイルへ書き込まない
```

## 8. TotpGenerator

### TotpGeneratorの責務

- Base32形式のTOTPシークレットを検証する
- RFC 6238準拠のコードを生成する
- 桁数、時間ステップ、アルゴリズムを管理する

### TotpGeneratorのインターフェース定義

```python
class TotpGenerator:
    def __init__(
        self,
        clock: Clock,
        digits: int = 6,
        interval_seconds: int = 30,
        algorithm: str = "SHA1",
    ) -> None:
        ...

    def validate_secret(self, secret: str) -> None:
        """Base32シークレットの形式を検証する"""
        ...

    def generate(self, secret: str) -> str:
        """現在時刻に対応するTOTPコードを生成する"""
        ...

    def remaining_seconds(self) -> int:
        """現在のTOTP有効期間の残り秒数を返す"""
        ...
```

## 9. ConfigManager

```python
class ConfigManager:
    def __init__(
        self,
        file_system: FileSystem,
        environment: Environment,
    ) -> None:
        ...

    def load(self, path: Path) -> AppConfig:
        """config.jsonを読み込む"""
        ...

    def save_key_path(self, path: Path, key_path: Path) -> None:
        """initでのみconfig.jsonのkey_pathを更新する"""
        ...

    def resolve(
        self,
        config_path: Path | None,
        cli_key_path: Path | None,
        cli_storage_path: Path | None,
    ) -> AppConfig:
        """CLI、環境変数、設定ファイル、既定値を統合して解決する"""
        ...
```

### パスの優先順位

```text
鍵パス:
1. --key
2. TOTP_KEY_PATH
3. config.jsonのkey_path
4. 未指定としてエラー

データファイルパス:
1. --storage
2. config.jsonのstorage_path
3. config.jsonと同じディレクトリのtotp-secrets.enc
```

`storage_path` が `config.json` に指定されていない場合でもエラーにはせず、
設定ファイルと同じディレクトリ直下の `totp-secrets.enc` を既定値として使用する。

## 10. ServiceRegistry

```python
class ServiceRegistry:
    def get(
        self,
        records: dict[str, SecretRecord],
        service_name: str,
    ) -> SecretRecord:
        ...

    def list_names(
        self,
        records: dict[str, SecretRecord],
    ) -> list[str]:
        """サービス名だけを返し、シークレットは返さない"""
        ...

    def add_or_update(
        self,
        records: dict[str, SecretRecord],
        record: SecretRecord,
    ) -> dict[str, SecretRecord]:
        ...

    def remove(
        self,
        records: dict[str, SecretRecord],
        service_name: str,
    ) -> dict[str, SecretRecord]:
        ...
```

## 11. CliHandler

### CliHandlerの責務

- CLI引数の初期取得
- 省略形コマンドの判定
- 予約サブコマンドとの衝突回避
- argparseによる正式な引数解析
- CLI例外のユーザー向けメッセージへの変換

### CliHandlerのインターフェース定義

```python
class CliHandler:
    RESERVED_COMMANDS = {
        "init",
        "generate",
        "get",
        "add",
        "remove",
        "rm",
        "list",
        "ls",
        "rekey",
        "config",
        "-g",
        "-h",
        "--help",
        "--version",
    }

    def __init__(
        self,
        parser_factory: ParserFactory,
        command_dispatcher: CommandDispatcher,
    ) -> None:
        ...

    def run(self, argv: list[str]) -> int:
        """CLI全体のエントリーポイント"""
        ...

    def normalize_argv(self, argv: list[str]) -> list[str]:
        """省略形を正式なgenerateコマンドへ変換する"""
        ...

    def prompt_for_key_output_path(self) -> Path:
        """initで--key未指定時に鍵の出力先を対話入力で取得する"""
        ...

    def confirm_existing_key_warning(self, path: Path) -> bool:
        """既存鍵の上書きに関する第1警告を確認する"""
        ...

    def confirm_decryption_loss_warning(self, path: Path) -> bool:
        """既存シークレットを復号できなくなる第2警告を確認する"""
        ...

    def confirm_rotation_limit_warning(self, path: Path) -> bool:
        """最古の鍵を削除するローテーション上限警告を確認する"""
        ...

    def parse(self, argv: list[str]) -> ParsedCommand:
        """正規化後の引数を解析する"""
        ...

    def dispatch(self, command: ParsedCommand) -> int:
        """解析済みコマンドをユースケースへ委譲する"""
        ...

    def handle_error(self, error: Exception) -> int:
        """安全なエラー表示と終了コード変換"""
        ...
```

## 12. CLIコマンド定義

```text
vtotp init [--key PATH]

vtotp generate SERVICE [--key PATH] [--storage PATH]
vtotp get SERVICE [--key PATH] [--storage PATH]
vtotp -g SERVICE [--key PATH] [--storage PATH]

vtotp add SERVICE [--secret SECRET] [--issuer ISSUER]
                  [--key PATH] [--storage PATH]

vtotp remove SERVICE [--force]
                    [--key PATH] [--storage PATH]
vtotp rm SERVICE [--force]
                 [--key PATH] [--storage PATH]

vtotp list [--key PATH] [--storage PATH]
vtotp ls [--key PATH] [--storage PATH]

vtotp rekey [--key PATH] [--storage PATH]

vtotp config
```

`config` は、現在解決される `config.json` のパス、マスター鍵パス、
暗号化ストレージパスを表示する。鍵の内容やTOTPシークレットは表示しない。

### パスオプションの扱い

`--key` と `--storage` は、暗号鍵ファイルと暗号化済みTOTPシークレットファイルのパスを実行時に一時指定するオプションとして正式に提供する。`--key` を指定しない場合は、`TOTP_KEY_PATH`、`config.json` の `key_path` の順に解決する。`--storage` を指定しない場合は、`config.json` の `storage_path`、設定ファイルと同じディレクトリの `totp-secrets.enc` の順に解決する。これらのオプションによる変更は実行中だけ有効で、`config.json` へ保存しない。

これらのオプションは、サブコマンド内の位置引数 `SERVICE` と前後を入れ替えて指定できる。`argparse` のサブパーサーでは、`SERVICE` を位置引数として定義し、`--key`、`--storage`、`--force` などをオプション引数として定義する。

```text
# いずれも同じ意味
vtotp get github --key PATH --storage PATH
vtotp get --key PATH --storage PATH github

vtotp rm github --force --key PATH --storage PATH
vtotp rm --force --key PATH --storage PATH github
```

`SERVICE` を最後に置く形式を正式にサポートする。ただし、`--key` または `--storage` の値は必ず同じ引数の直後に指定する。

`init` の `--key` は、新規鍵ファイルの出力先を指定する。`init` では `--storage` を受け付けない。暗号化データの保存先は `config.json` の `storage_path`、または未指定時の既定値（設定ファイルと同じディレクトリの `totp-secrets.enc`）を使用し、初期化時に既存の暗号化データを復号しない。

`--key` が指定されない場合は、対話入力で出力先を尋ね、入力された外部パスへ新規鍵を保存する。出力先が空の場合やキャンセルされた場合は初期化を中止する。`init` は生成した鍵のパスだけを `config.json` の `key_path` に保存する。

`init` の鍵出力先に既存ファイルがある場合は、上書き前に次の二段階確認を行う。

```text
1. 第1警告:
    指定された場所には既に鍵ファイルが存在する。新しい鍵で上書きするか確認する。

2. 第2警告:
    上書きすると、既存の暗号化データを現在の鍵で復号できなくなる可能性がある。
    既存のシークレットを失う危険を理解した上で続行するか確認する。

どちらか一方でも拒否、空入力、キャンセルされた場合は、鍵を上書きせず初期化を中止する。
```

`rekey` は、解決された鍵パスの鍵ファイル自体を更新する。`--key` が指定された場合はそのパスを一時的な更新対象として使用し、指定されない場合は `config.json` の `key_path` を使用する。`--key` による更新対象の変更は `config.json` に保存しない。

更新前の鍵ファイルは世代番号付きのファイルへ繰り上げ、同じ `<key_path>` に新しい鍵ファイルを配置する。暗号化済みTOTPシークレットデータはローテーション保存せず、同じ `storage_path` のファイルを新鍵でatomicに再暗号化する。

### 鍵ファイルのローテーション規則

```text
現在の鍵:       <key_path>
直前の鍵:       <key_path>.1
2世代前の鍵:    <key_path>.2
3世代前の鍵:    <key_path>.3
```

`MAX_ROTATED_KEYS = 3` とし、rekeyのたびに既存の鍵を次の世代へ繰り上げる。

```text
<key_path>.2 -> <key_path>.3
<key_path>.1 -> <key_path>.2
<key_path>   -> <key_path>.1
新鍵         -> <key_path>
```

`<key_path>.3` が存在する場合は、最初に次の警告を表示する。専用の強制オプションは設けない。

```text
第1警告:
ローテーション上限に達したため、最も古い鍵ファイル
<key_path>.3 を削除します。

第2警告:
この鍵を必要とするバックアップや過去の暗号化データは、
今後復号できなくなる可能性があります。続行しますか？
```

続行の明示応答が得られた場合だけ `<key_path>.3` を削除して繰り上げを実行し、拒否、空入力、キャンセルの場合はrekeyを中止する。暗号化済みTOTPシークレットファイルには `.1`、`.2`、`.3` のローテーションを作成しない。

### rekeyの鍵パス

`rekey` では旧鍵と新鍵を別々の引数で指定しない。更新対象のパスだけを指定する。

```text
vtotp rekey \
    --key KEY_PATH \
  --storage STORAGE_PATH
```

`--storage` を指定しない場合は `config.json` の `storage_path`、または設定ファイルと同じディレクトリの `totp-secrets.enc` を使用する。`--key` を指定しない場合は `config.json` の `key_path` を更新対象とする。

## 13. 省略形コマンドのフォールバック処理

### 予約サブコマンド

```text
init
generate
get
-g
add
remove
rm
list
ls
rekey
config
-h
--help
--version
```

### ロジックフロー

```text
入力:
    argv = ["github"]

1. argvが空か確認
   - 空の場合、helpを表示して終了

2. 第一引数を取得
   first = argv[0]

3. 第一引数がオプションか確認
   - -h、--help、--versionなどの場合、argparseへそのまま渡す

4. 第一引数が予約サブコマンドか確認
   - 予約済みの場合、argvを変更せず正式なサブコマンドとして解析する

5. 第一引数が予約サブコマンドでない場合
   - サービス名と判定する
   - argvを次のように変換する

       ["github", "--key", "keyfile"]
       ↓
       ["generate", "github", "--key", "keyfile"]

6. 変換後のargvをargparseへ渡す

7. ParsedCommandをCommandDispatcherへ渡す

8. generate処理を実行する

9. 成功時はTOTPコードだけを標準出力へ出力し、終了コード0を返す

10. 失敗時は秘密情報を含まないエラーを標準エラーへ出力する
```

### 擬似コード

```python
RESERVED_COMMANDS = {
    "init",
    "generate",
    "get",
    "add",
    "remove",
    "rm",
    "list",
    "ls",
    "rekey",
    "-h",
    "--help",
    "--version",
}


def normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ["--help"]

    first = argv[0]

    if first in RESERVED_COMMANDS:
        return argv

    if first.startswith("-"):
        return argv

    return ["generate", first, *argv[1:]]
```

### コマンド名とサービス名が衝突する場合

```text
vtotp init
```

これはサービス名 `init` ではなく、予約サブコマンドとして扱う。サービス名が `init` の場合は、次のように明示する。

```text
vtotp get init
vtotp generate init
```

## 14. コマンド実行の依存関係

### generate / get

```text
CliHandler
    -> ConfigManager
    -> KeyManager.load_key()
    -> SecureStorage.load()
    -> ServiceRegistry.get()
    -> TotpGenerator.generate()
    -> OutputWriter.write_code()
```

### add

```text
CliHandler
    -> ConfigManager
    -> KeyManager.load_key()
    -> SecureStorage.load()
    -> SecretInputReader.read_secret()
    -> TotpGenerator.validate_secret()
    -> ServiceRegistry.add_or_update()
    -> SecureStorage.save()
```

### init

```text
CliHandler
    -> ConfigManager
    -> CliHandler.prompt_for_key_output_path()  # --key未指定時のみ
    -> KeyManager.check_existing_key(key_output_path)
    -> CliHandler.confirm_existing_key_warning()  # 既存の場合のみ、第1警告
    -> CliHandler.confirm_decryption_loss_warning()  # 既存の場合のみ、第2警告
    -> KeyManager.create_key_file(key_output_path)
    -> SecureStorage.initialize()
    -> ConfigManager.save_key_path(config_path, key_output_path)
```

`init` では `config.json` の `key_path` だけを更新する。暗号化データの保存先は `config.json` の `storage_path`、または未指定時の既定値（設定ファイルと同じディレクトリの `totp-secrets.enc`）を使用し、初期化時に既存の暗号化データを復号しない。

### rekey

```text
CliHandler
    -> ConfigManager
    -> ConfigManager.resolve(cli_key_path, cli_storage_path)
    -> KeyManager.load_key(target_key_path)
    -> KeyManager.generate_key()
    -> SecureStorage.prepare_rekey(storage_path, old_key, new_key)
    -> CliHandler.confirm_rotation_limit_warning(target_key_path)  # .3が存在する場合のみ
    -> KeyManager.rotate_key_file(target_key_path, new_key)
    -> SecureStorage.commit_rekey(storage_path, prepared_path)
```

`rekey`では、まず対象世代と上限到達の有無を確認する。上限警告に続行応答が得られた場合、旧鍵でデータを復号して新鍵で暗号化した一時ファイルを作成・検証し、その後に鍵ファイルを世代番号付きで繰り上げ、新鍵を `<key_path>` へ配置し、暗号化データをatomicに置き換える。警告への明示的な続行応答がない場合は開始前に中止する。暗号化済みシークレットデータにはローテーション用の `.1`、`.2`、`.3` を作成しない。`rekey`完了後も `config.json` は変更しない。

### config

```text
CliHandler
    -> ConfigManager
    -> KeyManager.resolve_key_path()
    -> CliHandler._resolve_storage_path()
    -> OutputWriter.write_config()
```

`config` は、`config.json` のパス、鍵パス、暗号化ストレージパスを表示する。
鍵の内容やTOTPシークレットは表示しない。鍵パスが未設定の場合は、鍵パスを
`(未設定)` と表示し、ストレージパスは通常の既定値解決結果を表示する。

## 15. 終了コード

```text
0   成功
1   一般エラー
2   CLI引数エラー
3   鍵ファイル不在・不正
4   暗号化データ破損または復号失敗
5   指定サービス未登録
6   TOTPシークレット不正
7   ユーザーキャンセル
```

## 16. テスト設計

### Unit Test

```text
- 32バイト鍵が生成される
- 不正サイズの鍵を拒否する
- 暗号化と復号で元データが復元される
- 改ざんされた暗号文を拒否する
- サービスの追加・更新・削除が機能する
- TOTPコードが固定時刻で期待値になる
- 予約コマンドがgenerateへ変換されない
- 未予約語がgenerateへ変換される
- --helpや--versionがフォールバックされない
```

### Integration Test

```text
- initからgenerateまでの一連の操作
- addからlistまでの操作
- removeの確認処理と--force
- rekey後も既存サービスのTOTPが生成できる
- rekey後の鍵ファイルが同じパスに配置される
- rekey前の鍵ファイルが`<key_path>.1`へ退避される
- 既存の`.1`、`.2`が正しい世代へ繰り上げられる
- `<key_path>.3`が存在する場合は上限警告を表示する
- 上限警告への明示的な続行応答がない場合はrekeyを中止する
- 上限警告で続行した場合だけ`<key_path>.3`を削除する
- rekey後の暗号化データにローテーション用の`.1`ファイルを作成しない
- 旧鍵ではrekey後の暗号化データを復号できない
- `--key`指定時は対象パスだけが更新され、config.jsonが変更されない
- 鍵ファイルがない場合の終了コード
- 暗号化ファイルが破損した場合の終了コード
- Windows形式のパスを扱える
```

## 17. セキュリティ上の留意点

```text
- Pythonでは完全なメモリ消去を保証しにくいため、
  シークレットを長時間保持せず処理スコープを限定する。

- 秘密情報を例外メッセージ、デバッグログ、argparseのusage表示へ混入させない。

- --secretで渡した値はOSのプロセス一覧やシェル履歴に残る可能性があるため、
  未指定時の対話入力を推奨する。

- 暗号化ファイルには認証付き暗号を使用する。

- ファイル保存は一時ファイルとatomic renameを利用する。

- サービス名は空文字、パス区切り、制御文字を拒否する。

- listではサービス名だけを出力し、シークレットを表示しない。

- 鍵ファイルと暗号化データを同一媒体に置く場合、端末固定の保護強度が
  下がるため、運用ドキュメントで明示する。
```
