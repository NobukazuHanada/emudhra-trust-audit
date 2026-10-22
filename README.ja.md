[English](README.md) | [日本語](README.ja.md)

# emudhra-trust-audit

**非公式の独立したプロジェクトです。eMudhraとは提携しておらず、同社が運営・推奨するツールでもありません。**

[eMudhra中間CA鍵の問題](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)を調査するRust製CLIと、Claude Code／Codex向けの2スキルです。実行ファイルにIOCデータを同梱しています。**利用者はPython・Rust・Cargoなどの言語ランタイムを導入する必要がありません。** マルウェア検査ではなく、「検出なし」は安全の証明でもありません。

- **endpoint-trust-audit**：端末のCAバンドル、TLS上書き設定、クライアント設定を調査し、明示的な許可があればOSストアや導入済みツールも照会します。
- **project-trust-audit**：プロジェクト内の依存、ロックファイル、CAバンドル、ツール指定、コンテナ、CI、TLS設定を、プロジェクトのコードを実行せず調査します。

既定の監査はローカルファイルの読取りだけです。データ取得、報告送信、信頼ストア変更、パッケージ導入、自動修復は行いません。`--output` を明示した場合だけ新規レポートを保存し、既存ファイルは上書きしません。

## 対応環境と配布

| 環境 | アーカイブのターゲット名 |
| --- | --- |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Linux x86_64 | `x86_64-unknown-linux-musl` |
| Linux arm64 | `aarch64-unknown-linux-musl` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

Linux配布版はmuslを使い、glibcのバージョンに依存しない構成です。macOSとWindowsでは標準のOS機能を使います。CIはホストされたLinux・macOS・Windowsで検証しますが、過去の全OSバージョン、企業ポリシー、実ストアでの動作を保証しません。バイナリの署名・公証は現時点では行っていません。

[GitHub Releases](https://github.com/NobukazuHanada/emudhra-trust-audit/releases)から環境に合うアーカイブと `SHA256SUMS` を取得し、展開前にSHA-256を一覧の該当行と照合してください。例：

```sh
# Linux
sha256sum emudhra-trust-audit-x86_64-unknown-linux-musl.tar.gz
# macOS
shasum -a 256 emudhra-trust-audit-aarch64-apple-darwin.tar.gz
```

```powershell
# Windows PowerShell
Get-FileHash .\emudhra-trust-audit-x86_64-pc-windows-msvc.tar.gz -Algorithm SHA256
tar -xf .\emudhra-trust-audit-x86_64-pc-windows-msvc.tar.gz
```

macOS／Linuxでは `tar -xzf ARCHIVE.tar.gz` で展開します。実行ファイルを直接起動するか、信頼できるPATH上のディレクトリへ置いてください。再配布時はライセンスと帰属表示を保持してください。未確認のダウンロードをシェルへ直接流し込まないでください。SHA-256は一覧との整合性を確認するもので、GitHubとは独立した発行者の真正性証明ではありません。

**Rustへの移行作業自体ではタグやReleaseを公開しません。** タグ付きReleaseが公開されるまではソースからビルドするか、手動の [Release artifactsワークフロー](https://github.com/NobukazuHanada/emudhra-trust-audit/actions/workflows/release.yml)が成功したrunの `release-assets-with-checksums` を利用してください。手動実行はアーカイブ生成だけで、Releaseを公開しません。

## ソースからビルド

開発者は[Rustツールチェーン](https://rust-lang.org/tools/install/)を用意します。Pythonは不要です。安定版 **Rust 1.99.1** を `rust-toolchain.toml` で固定し、最小対応Rustバージョン（MSRV）も1.99.1としています。ビルド依存は `Cargo.lock` に固定しており、ビルド時にダウンロードする場合があります。

```sh
git clone https://github.com/NobukazuHanada/emudhra-trust-audit.git
cd emudhra-trust-audit
cargo build --locked --release
./target/release/emudhra-trust-audit data --verify
```

Windowsでは `.\target\release\emudhra-trust-audit.exe` を実行します。監査に必要なのはビルド済み実行ファイルだけで、インタープリター、パッケージ導入、隣接するデータディレクトリは不要です。この移行ではcrates.ioへのパッケージ公開も行いません。

## 監査を実行する

```sh
emudhra-trust-audit endpoint --format json
emudhra-trust-audit project /path/to/project --format json
emudhra-trust-audit data --verify
emudhra-trust-audit explain PROJECT-TLS-VERIFY-NODE-ENV
```

Windowsでカレントディレクトリにある実行ファイルを使う場合は `.\emudhra-trust-audit.exe` と指定します。空白を含むパスは引用符で囲んでください。

- `endpoint --bundle PATH`／`project --scan-bundle FILE`：明示した追加CAソースを検査します。
- `endpoint --commands`：信頼できる導入済み実行ファイルの照会を許可します。プロジェクト由来のシェル文字列ではなく、固定の引数列を使用します。ただしツール自身や起動フックは書込み・ダウンロード・テレメトリー送信を行う可能性があります。既定の `--no-commands` が優先されます。
- `endpoint --no-user-stores`：ユーザー別ストアとユーザーのクライアント設定を除外します。
- `endpoint --network-test HOST --commands`：導入済みOpenSSLによるTLS接続を明示的に許可します。送信元IPなどの接続情報が相手に伝わります。443番ポートのホスト名・IPを受け付け、URLやシェル式は受け付けません。接続失敗はCA拒否の証明ではなく、1クライアント・1チェーンの結果を他へ一般化できません。
- `project --no-containers`：コンテナ固有検査を省きます。
- `--format json|text|sarif`：出力形式を選択します。`--output NEW_FILE` で明示的に保存できます。
- `--data-dir DIR`：同梱データの代わりに、レビュー済みの外部データを使います。ネットワーク更新は行いません。

管理者権限は不要です。読めないストアは検査不足として報告します。

## Claude Code／Codexのスキル

各配布アーカイブには `skills/endpoint-trust-audit/` と `skills/project-trust-audit/` があり、それぞれにバイナリとライセンスを同梱します。必要なフォルダを**丸ごと**以下へコピーしてください。

| ホスト | 個人用 | プロジェクト用 |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.agents/skills/` | `.agents/skills/` |

Windowsの `~` はユーザープロファイルです。確実に再検出させるにはアシスタントのセッションを再起動してください。場所は [Claude Code](https://code.claude.com/docs/en/skills) と [Codex](https://learn.chatgpt.com/docs/build-skills) の公式資料に基づきます。ソースのスキルフォルダにはバイナリを含まないため、CLIをビルドして信頼できるPATHに置くか、アシスタント起動前に `EMUDHRA_TRUST_AUDIT_BIN` へ絶対パスを設定してください。

Claude Codeでは `/endpoint-trust-audit`／`/project-trust-audit`、Codexでは `$endpoint-trust-audit`／`$project-trust-audit` を指定し、「端末をオフラインで検査」「現在のプロジェクトを変更せず検査」と依頼します。

ラッパーは引数と終了コードを保持します。

```sh
sh /absolute/skill-dir/run.sh --format json          # endpoint skill
sh /absolute/skill-dir/run.sh /path/to/project --format json  # project skill
```

```powershell
& 'C:\absolute\endpoint-trust-audit\run.ps1' --format json
& 'C:\absolute\project-trust-audit\run.ps1' . --format json
```

明示したバイナリ、同梱バイナリ、信頼できるPATH上のアプリケーションの順に選びます。未導入なら導入案内と終了コード3を返し、自動ダウンロードしません。組織の実行ポリシーを回避せず、ラッパーが制限される場合は信頼できるCLIを直接実行してください。検査対象はスキルのフォルダではなく、ユーザーのプロジェクトです。

## 出力と解釈

JSONは `schema_version`、`tool_version`、`scope`、`verdict`、`action`、`exit_code`、`findings`、`data_sources`、`notes`、`errors` を含みます。各findingに根拠、信頼度、対処案、出典、位置参照を記録します。

| status | 意味 |
| --- | --- |
| `known_indicator` | IOC・規則との一致。傍受の証明ではない |
| `suspicious` | 確認が必要なヒューリスティック |
| `not_found` | 実施できた検査では見つからない |
| `unable_to_assess` | 証拠不足・未対応・読取り不可。合格ではない |

| 終了コード | 意味 |
| --- | --- |
| 0 | 実施済み検査から追加対策なし。安全保証ではない |
| 1 | 検査不足を含む要確認 |
| 2 | 要対策 |
| 3 | 監査・入力・整合性・出力エラー |

`UNKNOWN` と要対策は両立します。鍵の保存、ブロックリスト、バージョンだけで実効受理・拒否を証明できません。Rust CLIは `EXPOSED`／`BLOCKED` を断定しません。`INSECURE` は既知のTLS無効化設定が見つかったことを示すので、実際の用途を確認し最初に報告します。ドキュメント上の記述は重要度を下げ、テスト用の設定も人が用途を確認します。

位置はファイル名ではなく `file:<hash>` 形式です。既知のプロジェクト相対パスは、ローカルで `emudhra-trust-audit file-id path/to/file` を実行すると照合できます。生のソース行、個人パス、証明書subject、プロキシ値、認識できないバージョン文字列は出力しません。

## 検査範囲・プライバシー・限界

PEM／DERのSPKIとJKS／JCEKSの信頼証明書エントリを解析します。秘密鍵の復号やキーストアのパスワードダイジェスト検証はしません。macOSキーチェーン、WindowsのRoot／CA／Disallowed列挙は `--commands` が必要で、Windows更新ポリシーも解析します。macOS／Windowsの既定動作はファイル検査です。

npm、Yarn、pnpm、requirements、Poetry／uv／PDM／Cargoのロック、Pipfile、Composer、Bundler、Hex、Go、`.nvmrc`、`.node-version`、`.go-version`、`.tool-versions`、単純なmise指定の部分的パーサーを持ちます。CIのランタイム指定、コンテナのCA更新・ダイジェスト固定も調べます。未対応形式、不正データ、ロック欠落、未知のブランチ、数値以外やプレリリースを含む汎用バージョンは検査不足とします。一般的なCVE／SCAスキャナーや依存リゾルバーではありません。

プロジェクトは20,000ディレクトリエントリ・1ファイル1 MiBが上限です。リンク／reparse point、特殊ファイル、大きなファイル、不正UTF-8は除外して報告します。ビルド・依存ディレクトリは対象外です。除外ファイル名は `.ca-trust-audit-ignore` を維持し、明示的な除外を報告します。端末バンドルとプローブ出力は16 MiB、プローブは10秒が上限です。

OSのCAシンボリックリンクは意図的に追跡します。親ディレクトリ差替えの競合を完全に隔離するものではないため、安定したローカルスナップショットを使ってください。ネットワークマウントはOS通信を発生させ得ます。外部ツールはサンドボックス化されません。コンテナ／WSLの結果はその環境だけに適用します。ブラウザの失効情報、Windows CTLの鮮度、プロセスのキャッシュ、PKCS#12／PKCS#7、全クライアントの実効検証は確立しません。Python／certifi環境は実行しません。`VIRTUAL_ENV`／`CONDA_PREFIX` 内の既知のcertifiバンドル・メタデータは直接読み取り、それ以外の環境はロックファイルと明示的なCAバンドルで別途検査します。

**オンラインのClaude／Codexへ出力を渡す行為は、スキャナーの通信とは別です。** 完全にローカルへ閉じる場合はCLIを直接使い、外部サービスへ報告を渡さないでください。パスのハッシュは相互照合可能で、暗号化ではありません。秘匿を解除するためにアシスタントへ生ファイルを読ませないでください。実際のスキル検出・呼出しや端末ポリシーは導入先での確認が必要です。

## 対処とデータ

OSの信頼パッケージ、ブラウザ、ランタイム、独自バンドルを公式経路で更新します。プロセスを再起動し、仮想環境、CI／コンテナイメージ、アプリケーションを再構築・再配備します。TLS検証の無効化や関連ルートの一律削除は行わないでください。監査はこれらの変更を自動実行しません。認証情報のローテーション対象は、実際の接続・認証・傍受の証拠で判断し、検査結果だけで「全部交換」「交換不要」と断定しません。

IOC・規則は `data/` に出典・日付・バージョン付きで管理します。SHA-256はCRLF／CRをLFへ正規化し、それ以外のバイト変更を検出します。整合性検査であり署名ではありません。同梱データはレビュー済みコミットと新バイナリで更新し、実行時の取得はしません。修正版表の多くは2026-10-21の[コミュニティ追跡サイト](https://emudhra.we-have-a-problem.com/)のスナップショットなので、保守時はベンダー資料を再確認してください。移行差分と残存リスクは [AUDIT.md](AUDIT.md) に記録しています。

## 開発・Release・ライセンス

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- data --verify
cargo run --locked --example maintenance -- skills
```

CIではcargo-denyでアドバイザリ、ライセンス、依存の取得元も検査します。製品実行時の依存は増えません。配布物にはロックされた依存のライセンス本文を含めます。Releaseワークフローは上記5ターゲットをビルド・実行検証し、アーカイブの `SHA256SUMS` を生成します。`v*` タグではReleaseを公開し、手動実行はActions成果物のアップロードだけです。明示的な承認なしにReleaseタグを作成しないでください。

[CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、[VALIDATION.md](VALIDATION.md)、[CHANGELOG.md](CHANGELOG.md)を参照してください。**Apache-2.0**で、[LICENSE](LICENSE)、[NOTICE](NOTICE)、第三者帰属表示を同梱します。合成証明書フィクスチャに秘密鍵は含みません。eMudhra、Anthropic、OpenAI、GitHubとの提携を示すものではありません。旧Pythonパッケージ／モジュール、Python固有のビルド・テスト・スキルヘルパーは削除しました。過去の検証はGit履歴に残っています。
