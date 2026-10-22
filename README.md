# ca-trust-audit

[eMudhra中間CA鍵の侵害](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)に関する、ローカル・読み取り専用の監査ツールと独立した2つのAgent Skillsです。マルウェア感染の検査ではありません。

- **endpoint-trust-audit**: macOS / Linux / WindowsのCAストア、CA上書き環境変数、TLS設定、ランタイム・CLIの調査。
- **project-trust-audit**: 指定プロジェクトの依存、ロックファイル、CAバンドル、ビルド・開発ツール、コンテナ・CI・TLS関連設定の静的調査。

Python 3.9以上、実行時の追加依存なし。既定では外部コマンド・ネットワーク・ファイル書き込みなし。自動修復はしません。これは初期版であり、**「検出なし」は「安全」の証明ではありません**。

## すぐ実行する

ソース一式を取得し、そのディレクトリから実行します。Windowsでは `python3 -B` を `py -3 -B` に読み替えてください。パスに空白がある場合は引用符で囲みます。

```sh
python3 -B bin/ca-trust-audit.py endpoint --format json
python3 -B bin/ca-trust-audit.py project /path/to/project --format json
python3 -B bin/ca-trust-audit.py data --verify
python3 -B bin/ca-trust-audit.py explain ENDPOINT-SPKI-TRUSTED
```

実行コマンドが必要なOSストア・バージョン調査は既定で判定不能になります。信頼できるインストール済みツールを調べる場合のみ `endpoint --commands` を明示します。実行ファイルのPATH、Pythonの起動フック、Nodeの環境設定等が信頼できない端末では使わないでください。`--no-commands` は `--commands` より優先します。

`--bundle PATH`（端末）と `--scan-bundle FILE`（プロジェクト）で追加バンドルを指定できます。`--output FILE` は明示した場合だけレポートを書きます。通常はstdoutのみです。`--network-test HOST` は任意の追加機能で、接続先へのIPアドレス等の開示に同意した場合だけ使用してください。別接続で取得した証明書とハンドシェイク結果を結びつけて、安全・危険を断定しません。

## Claude Code / Codexへの導入

リポジトリ直下の `skills/` は開発用です。次のコマンドで共通実装・IOCデータ・ライセンスを各スキルに同梱します。生成先が既存の場合は上書きせず停止します。

```sh
python3 scripts/build_skills.py dist/skills
```

生成された2つのフォルダを、必要なものだけ以下へ丸ごとコピーしてください。どちらも単独で動作し、もう一方のスキルや元のチェックアウトを必要としません。

| ホスト | 個人用 | プロジェクト用 |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex | `~/.agents/skills/` | `.agents/skills/` |

Windowsの `~` はユーザープロファイルディレクトリです。エクスプローラーでコピーでき、シンボリックリンクや管理者権限は不要です。スキルを再検出させるためセッションを再起動してください。導入場所は [Claude Code公式資料](https://code.claude.com/docs/en/skills) と [Codex公式資料](https://learn.chatgpt.com/docs/build-skills) に基づきます。

Claude Codeでは `/endpoint-trust-audit` または `/project-trust-audit`、Codexでは `$endpoint-trust-audit` または `$project-trust-audit` を指定し、例えば「この端末をオフラインで検査」「カレントプロジェクトを変更せず検査」と依頼します。

スキルの `run.py` は任意のカレントディレクトリから実行可能です。例：

```sh
python3 -B /absolute/path/endpoint-trust-audit/run.py endpoint --format json
python3 -B /absolute/path/project-trust-audit/run.py project . --format json
```

## 結果と終了コード

JSONは `schema_version`, `verdict`, `action`, `exit_code`, `findings`, `data_sources`, `notes`, `errors` を含みます。各findingに根拠・信頼度・出典・対策を収録します。`--format text` と `--format sarif` も利用できます。

| status | 意味 |
| --- | --- |
| `known_indicator` | IOC・規則との一致を観測 |
| `suspicious` | 文字列・パターン一致。実際の用途は要確認 |
| `not_found` | 実施できた検査の範囲では見つからない |
| `unable_to_assess` | 未対応、読み取り失敗、証拠不足などで判定不能 |

| 終了コード | 意味 |
| --- | --- |
| 0 | 実施した検査からの追加対策なし。安全保証ではない |
| 1 | 要確認・判定不能あり |
| 2 | 要対策項目あり |
| 3 | データ不整合、入力・実行エラー |

`UNKNOWN` と `action_required` は両立します。鍵が保存されている事実は対策検討の根拠になりますが、稼働クライアントの受理を証明しません。`EXPOSED` / `BLOCKED` は実効受理・拒否を示す予約済みの判定語であり、現在のストア・バージョン調査では断定しません。`INSECURE` はTLS検証無効化に関する所見を含むため、statusとconfidenceを確認してください。

## 検査範囲と限界

- OS別の既知パスと、オプトイン時のキーチェーン／Windowsストア・ランタイム・パッケージ照会を実装。macOS/Windowsの既定モードはファイル調査に限定されます。
- npm / Yarn / pnpm、requirements / Poetry / uv / Pipenv / PDM、Cargo、Go、Composer、Bundler、Hex等の限定的パーサーを収録。Bunバイナリ、NuGet、Gradle等は棚卸しのみで、判定不能として報告します。全形式・全構文・推移依存を完全に扱うものではありません。
- CA関連の既知パッケージを比較する専用監査です。一般的なCVE、改変パッケージ、悪性依存を網羅するSCAではありません。
- 既定で20,000ファイル・各1 MiBまで。シンボリックリンク、特殊ファイル、大きなファイル、依存インストール先、ビルド成果物等は対象外。`.ca-trust-audit-ignore` の除外は報告に記録されます。
- コンテナ内へ入る、イメージを取得する、パッケージを解決する、プロジェクトのスクリプトを実行する処理はありません。WSL・コンテナ内の結果はその環境だけに適用します。
- ローカルで中間証明書が見つからなくても、サーバーが提示するチェーンを信頼する場合があります。関連ルートの存在・削除だけでは安全性を断定できません。
- 失効情報、稼働プロセスのキャッシュ、ブラウザ独自ポリシー、Schannel/Authenticodeの実効検証、Java PKCS#12等は未検証または未対応です。
- Linuxでローカル検証済み。macOS/Windows向けには模擬応答テストとCIマトリクスを用意していますが、実機確認は別途必要です。

## 対処

OS・ブラウザ・CAパッケージ・ランタイムを公式経路から更新し、使用中のプロセスを再起動します。独自バンドル、仮想環境、CIイメージ・コンテナも更新して再構築・再配備し、再検査してください。TLS検証の無効化を回避策にしないでください。ルート証明書を一律に削除しないでください。

認証情報のローテーションは、実際の接続・認証・改変の証拠を調査して対象を決めます。一律に「全部交換」「交換不要」と判断しません。スキャナーは認証情報も信頼設定も変更しません。

## プライバシーと脅威モデル

既定のスキャナーは外部送信しません。ソース行、トークン、プロキシURL、秘密鍵本文をレポートへ出さず、ユーザー名・ホームパスを伏せます。報告には相対ファイル名、公開パッケージ名、バージョンなどが含まれるため、共有前に確認してください。任意のファイル名へ埋め込まれた未知の秘密を完全に識別できる保証はありません。

**オンラインのClaude/Codexへ出力を渡す行為は、スキャナー自身の通信とは別です。** 完全に端末内に閉じる必要がある場合はCLIを直接実行し、出力を外部サービスに渡さないでください。AIに生の設定ファイルを追加で貼り付けさせないでください。信頼できないディレクトリは変更されないスナップショットで調査してください。

## データ・開発・ライセンス

IOC・規則・修正版表は `data/` に分離し、出典URL・更新日・版・SHA-256を記録しています。ネットワーク更新はせず、変更はレビューするコミットとして管理します。ハッシュは整合性確認であり、署名や出典の正しさの保証ではありません。修正版表の多くは[コミュニティ追跡サイト](https://emudhra.we-have-a-problem.com/)に基づく2026-10-21のスナップショットです。保守時は各ベンダーの一次資料と再照合してください。

[CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、[CHANGELOG.md](CHANGELOG.md)を参照してください。Apache-2.0で公開するためのソース一式です。[LICENSE](LICENSE)・[NOTICE](NOTICE)を同梱しています。eMudhra、Anthropic、OpenAI、GitHubとの提携・推奨関係はありません。第三者の修復スクリプトや侵害証明書は同梱せず、テスト証明書は合成フィクスチャです。

## 独立監査（2026-10-22）

再監査の変更・検証・残存リスクは [AUDIT.md](AUDIT.md) に記録しています。
プロジェクトのリンクは読取り直前にも拒否し、端末の証明書・キーストアは上限付きの通常ファイル読取りに限定しています。端末のOS証明書リンクは正規のストアで使われるため追跡します。プロジェクトの既定上限は1 MiB、端末のバンドル読取りは通常16 MiB（証明書ファイルAPIは32 MiB）です。

`--commands` はプロセスの隔離機能ではありません。起動フックやツール自身の通信・書込みまで保証できません。オフライン保証が必要なら既定モードとローカルの固定スナップショットを使用してください。ネットワークマウントの読取りはOS側で通信し得ます。実行中に親ディレクトリが差し替わる競合を全OSで原子的に防ぐものではありません。

`.nvmrc` / `.node-version` / `.go-version` / `.tool-versions` と単純な mise `[tools]` バージョン指定を比較します。未解析のmanifestも検査不足として報告します。コメント・条件分岐・テスト内のTLS設定や複雑なTOMLは静的パターン検査の限界があり、結果の用途確認が必要です。
