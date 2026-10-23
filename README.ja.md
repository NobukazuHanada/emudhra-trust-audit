[English](README.md) | [日本語](README.ja.md)

# emudhra-trust-audit

**非公式・独立したプロジェクトです。eMudhra、Anthropic、OpenAI とは提携しておらず、承認や運営も受けていません。**

2026年の [eMudhra 中間 CA 弱鍵インシデント](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) の影響を調べる、Claude Code と Codex 向けの読み取り専用スキル2つです。
中身は手順とデータ（`SKILL.md` と Markdown の参照資料）だけです。
**導入に Python、Node.js、Rust、パッケージ、ダウンロードするバイナリは要りません。**
エージェントは OS に標準で入っている読み取り専用コマンドを、決められた形で実行します。

- **endpoint-trust-audit**：このコンピューターを調べます。システムの CA バンドル、OS の信頼ストア、キーチェーン、CA 上書きファイルの証明書をハッシュ化し、侵害された8つの SPKI SHA-256 値と照合します。OS の CA パッケージのバージョンと、TLS 検証を無効にする設定も確認します。
- **project-trust-audit**：リポジトリを調べます。同梱された CA バンドルをハッシュ化し、コード・設定・コンテナ・CI にある TLS 検証の回避や独自 CA の上書きを探します。ロックファイルとツール指定のバージョンも修正版と比べます。プロジェクトのコードは実行しません。

マルウェアスキャナーではありません。**「検出なし」は安全の保証ではありません。**

## 導入

プラグインは2つあり、それぞれにスキルが1つ入っています。必要な方だけでも、両方でも導入でき、どちらも単独で動きます。

### Claude Code

```sh
claude plugin install endpoint-trust-audit --marketplace NobukazuHanada/emudhra-trust-audit
claude plugin install project-trust-audit --marketplace NobukazuHanada/emudhra-trust-audit
```

各行は、必要ならこのリポジトリをマーケットプレイス `emudhra-trust-audit` として追加し、プラグインを1つ導入します。
お使いの Claude Code が `--marketplace` を受け付けない場合は、先にマーケットプレイスを追加します。

```sh
claude plugin marketplace add NobukazuHanada/emudhra-trust-audit
claude plugin install endpoint-trust-audit@emudhra-trust-audit
claude plugin install project-trust-audit@emudhra-trust-audit
```

### Codex

```sh
codex plugin marketplace add NobukazuHanada/emudhra-trust-audit
codex plugin add endpoint-trust-audit@emudhra-trust-audit
codex plugin add project-trust-audit@emudhra-trust-audit
```

### プラグイン機能を使わない場合

このリポジトリをダウンロードし（GitHub の **Code → Download ZIP**）、必要なスキルのフォルダを個人用スキルのディレクトリへコピーします。Claude Code は `~/.claude/skills/`、Codex は `~/.agents/skills/` です。

- `plugins/endpoint-trust-audit/skills/endpoint-trust-audit/`
- `plugins/project-trust-audit/skills/project-trust-audit/`

各フォルダは単体で動きます。

### 0.3.0 からの移行

0.3.0 では2つのスキルを `emudhra-trust-audit` という1つのプラグインで配布していました。新しいプラグインを導入する前に削除してください：
`claude plugin uninstall emudhra-trust-audit@emudhra-trust-audit` または
`codex plugin remove emudhra-trust-audit@emudhra-trust-audit`。

## 更新

| ツール | コマンド |
| --- | --- |
| Claude Code | `claude plugin marketplace update emudhra-trust-audit` の後に、`claude plugin update endpoint-trust-audit@emudhra-trust-audit` と `claude plugin update project-trust-audit@emudhra-trust-audit` のうち導入済みのもの（セッションを再起動） |
| Codex | `codex plugin marketplace upgrade emudhra-trust-audit` の後に、`codex plugin add endpoint-trust-audit@emudhra-trust-audit` と `codex plugin add project-trust-audit@emudhra-trust-audit` のうち導入済みのもの |
| 手動コピー | コピーしたフォルダを置き換える |

## 削除

| ツール | コマンド |
| --- | --- |
| Claude Code | `claude plugin uninstall endpoint-trust-audit@emudhra-trust-audit` と `claude plugin uninstall project-trust-audit@emudhra-trust-audit` のうち導入済みのものの後に、`claude plugin marketplace remove emudhra-trust-audit` |
| Codex | `codex plugin remove endpoint-trust-audit@emudhra-trust-audit` と `codex plugin remove project-trust-audit@emudhra-trust-audit` のうち導入済みのものの後に、`codex plugin marketplace remove emudhra-trust-audit` |
| 手動コピー | コピーしたフォルダを削除する |

## 使い方

普通の言葉で頼んでください。例：「このコンピューターは侵害された eMudhra の CA 鍵をまだ信頼していますか？」「このリポジトリを eMudhra CA インシデントの観点で監査して」。

- Claude Code：関係する質問ではスキルが自動で読み込まれます。`/endpoint-trust-audit:endpoint-trust-audit` と `/project-trust-audit:project-trust-audit` で直接呼ぶこともできます（手動コピーの場合は `/endpoint-trust-audit` と `/project-trust-audit`）。
- Codex：関係する質問ではスキルが自動で読み込まれます。依頼文で `endpoint-trust-audit` や `project-trust-audit` を名指しすることもできます。

プロジェクトを監査するときは、リポジトリのルートでエージェントを起動してください。Claude Code と Codex は、権限設定に応じてコマンド実行前に承認を求めます。各コマンドを確認してください。

## 権限

エージェントが実行するのは、各スキルの `references/` にあるコマンド集のブロックだけで、書き換えずにそのまま実行します。

- Linux/macOS：`sh`、`awk`、`find`、`grep`、`cat`、`openssl`、`uname`、`printenv`。存在する場合は `security`（macOS）、`dpkg-query`、`rpm`、`pacman`、`apk` も使います。`PATH` は OS のディレクトリに固定します。
- Windows：標準の Windows PowerShell 5.1 か PowerShell 7 を使い、`Cert:\` ストア、いくつかのファイル、環境変数、レジストリ値2つを読みます。

スキルは次のことを禁止しています：インストール、変更、削除、権限昇格（`sudo` や管理者として実行）、プロジェクトのコードの実行、OS 以外のプログラム（`node` や `python` など）の実行、ネットワークアクセス。
コマンドに信頼できない値を埋め込むこともしません。ファイルの中身は標準入力で渡し、ファイル名は `find` 経由でのみ渡します。
Windows では、環境変数が指す CA ファイルをローカルドライブ上のものに限って開くため、監査がファイルサーバーへ接続することはありません。
各ブロックは1回だけ、120秒のタイムアウト付きで実行し、量を制限した要約だけを出力します。
これらはエージェントへの指示であって、サンドボックスではありません。実際に止める役目は、お使いのエージェント自身の権限確認です。

## プライバシー

スキル自体は何も外部へ送信しません。ただしエージェントはコマンドの出力を読み、その出力は利用中の AI サービス（Anthropic または OpenAI）がそれぞれの規約に従って処理します。
送られる量を減らすため、コマンドが出力するのはラベル、件数、ハッシュ、バージョン、一致した設定の断片と、ロックファイルについてはバージョンを含む数行（切り詰め済み）だけです。ファイル全体は出力しません。URL に含まれる認証情報は、出力前に `<redacted>` へ置き換えます。
報告のルールでは、ホームのパス、ユーザー名、秘密情報、証明書のサブジェクトを伏せます。詳しくは [PRIVACY.md](PRIVACY.md) を参照してください。

## 判定

各チェックの結果は次のいずれかです。

| 状態 | 意味 |
| --- | --- |
| `known_indicator` | 完全一致：侵害された SPKI、TLS 検証を無効にする設定、修正版より古いバージョン |
| `suspicious` | 人による確認が必要 |
| `not_found` | チェックを最後まで実行し、何も見つからなかった（そのチェックの範囲に限る） |
| `unable_to_assess` | 確認できなかった。合格の意味には決してならない |

各所見には、根拠、信頼度、場所、利用者が取れる対策、データの出典が付きます。総合判定は ACTION REQUIRED（対応が必要）、REVIEW REQUIRED（確認が必要）、NO ACTION IDENTIFIED IN COMPLETED CHECKS（完了したチェックでは対応事項なし）のいずれかです。
認証情報についての助言は根拠に応じて変わります。一律のローテーションを指示することも、不要だと断言することもありません。

## 限界

- OS 標準コマンドで確認できないものは `unable_to_assess` として報告します：ブラウザーや NSS のストア、Java のキーストア、ルート証明書を内蔵するランタイム（Node.js、Go、Electron、Deno）、実際にチェーンが受け入れられるかどうか、失効情報の鮮度、傍受が実際に起きたかどうか。
- Windows では P-384 の鍵だけをハッシュ化します。8つの指標はすべて P-384 なので、他の鍵種別が一致することはありません。
- 侵害された SPKI が存在していても、クライアントがそれを受け入れることの証明にはなりません。
- テキストのルールは、難読化された設定を見逃したり、無害な文字列に一致したりすることがあります。
- コンテナや WSL での結果は、それ自身についてだけで、ホストの状態は表しません。
- 指標データは日付つきのスナップショットです（事実は 2026-10-21 時点、データ版 2026.10.22）。スキルが更新を取得することはありません。

## データと出典

各スキルには `references/indicators.md` と `fixed-versions.md` が入っており、プロジェクト用にはさらに `tls-rules.md` があります。どれも出典 URL、取得日、データの版を記載しています。
出典は Mozilla、Google、eMudhra、Cloudflare、CISA とコミュニティのトラッカーです。[NOTICE](NOTICE) を参照してください。

## マーケット公開の状況

- このリポジトリ自体が、Claude Code（`.claude-plugin/marketplace.json`）と Codex（`.agents/plugins/marketplace.json`）向けのプラグインマーケットプレイスになっています。上の導入コマンドはこれを使います。
- Anthropic のプラグインディレクトリにも OpenAI のプラグインディレクトリにも、まだ申請して**いません**。どちらも各社への申請と審査が必要で、掲載される保証はありません。プラグイン名には第三者のブランドを含めていませんが、インシデントを示すために説明文とマーケットプレイス名で eMudhra に言及しています。ブランドの使い方は両ディレクトリの審査対象です。

## Rust CLI（保存済み）

以前の単体 Rust コマンドラインツールは、変更を加えずに [`archive/rust-cli`](https://github.com/NobukazuHanada/emudhra-trust-audit/tree/archive/rust-cli) ブランチ（コミット `3233891a5578630200f95ccbd74577553e2b4845`）に保存しています。`main` ではもう保守しておらず、バイナリのリリースも公開していません。

## リポジトリ構成

```text
.claude-plugin/marketplace.json      Claude Code 用マーケットプレイス
.agents/plugins/marketplace.json     Codex 用マーケットプレイス
plugins/endpoint-trust-audit/        プラグイン1（プラグイン2も同じ構成）
  .claude-plugin/plugin.json         Claude Code 用 manifest
  .codex-plugin/plugin.json          Codex 用 manifest
  skills/endpoint-trust-audit/       SKILL.md と references/
plugins/project-trust-audit/         プラグイン2
  skills/project-trust-audit/        SKILL.md と references/
scripts/validate.sh                  CI 用チェック（メンテナー専用）
```

## 貢献・セキュリティ・ライセンス

[CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、[CHANGELOG.md](CHANGELOG.md) を参照してください。ライセンスは [Apache-2.0](LICENSE) です。
「eMudhra」と「emSign」は eMudhra Limited の商標で、影響を受けた認証局を示すためだけに使っています。
