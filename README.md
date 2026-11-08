# security-guard

Claude Code が秘密情報を漏らしたり、取り返しのつかないコマンドを実行したりするのを防ぐプラグインです。
A Claude Code plugin that blocks secrets from being written, blocks reads of sensitive files, and asks before dangerous shell commands.

## できること

| 種類 | 対象 | 動作 |
|---|---|---|
| 秘密情報の書き込み | Write / Edit / NotebookEdit の内容、Bash / PowerShell のコマンド | **ブロック** |
| 機密ファイルへのアクセス | Read / Write / Edit、コマンド中のファイル名 | **ブロック** |
| 危険なコマンド | Bash / PowerShell | **実行前に確認** |

### 検出する秘密情報
AWS アクセスキー、秘密鍵（`-----BEGIN ... PRIVATE KEY-----`）、GitHub トークン、Anthropic / OpenAI の API キー、Slack トークン、Google API キー、Stripe の本番キー、JWT

### 機密ファイル
`.env` と `.env.*`（`.env.example` / `.sample` / `.template` などは除く）、`*.pem` / `*.key` / `*.p12` / `*.pfx`、`id_rsa` / `id_ed25519` など（`.pub` は除く）、`.aws/credentials`、`.netrc`、`.git-credentials`、`credentials.json`、サービスアカウントの JSON

### 確認を求めるコマンド
`rm -rf`、`Remove-Item -Recurse -Force`、`curl ... | sh` / `irm ... | iex`、`Invoke-Expression`、`git push --force`、`git reset --hard`、`git clean -f`、`chmod 777`、`sudo`、`mkfs` / `dd of=/dev/...` / `format`、`Set-ExecutionPolicy`、Defender の無効化

## インストール

Claude Code のプロンプトで次を実行します。

```
/plugin install security-guard --marketplace kushinoyuya/security-guard
```

マーケットプレイスを追加するか聞かれたら `y` を押し、続けてインストール先のスコープを選びます（通常は user スコープのまま Enter）。

ターミナルから実行する場合:

```
claude plugin install security-guard --marketplace kushinoyuya/security-guard
```

## 開発

```
claude --plugin-dir ./           # このフォルダから読み込んで起動（保存すると自動で再読み込み）
claude plugin validate .         # 構成のチェック
claude plugin test .             # テストの実行
```

検出ルールは `hooks/rules.ts` にまとめてあります。パターンを追加・変更したら、`hooks/register.test.ts` にもテストを追加してください。

## 注意

このプラグインは代表的なパターンを正規表現で検出する補助的な仕組みです。すべての漏洩や危険な操作を防げるわけではありません。gitleaks などのスキャナーや、権限設定と組み合わせて使ってください。

## ライセンス

MIT
