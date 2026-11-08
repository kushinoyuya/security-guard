// Detection rules for security-guard. Pure functions, no engine access,
// so they can be tested on their own.

/** Known secret formats: [label, pattern]. */
export const SECRET_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ['AWS access key', /\b(AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['private key', /-----BEGIN ([A-Z]+ )?PRIVATE KEY( BLOCK)?-----/],
  ['GitHub token', /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI API key', /\bsk-(proj-|svcacct-)?[A-Za-z0-9_-]{32,}/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['Stripe live key', /\b[sr]k_live_[0-9A-Za-z]{24,}/],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
]

/** Returns the label of the first secret found in `text`, or undefined. */
export function findSecret(text: string): string | undefined {
  for (const [label, re] of SECRET_PATTERNS) {
    if (re.test(text)) return label
  }
  return undefined
}

const SAFE_ENV = /\.env\.(example|sample|template|dist|defaults)$/i

/** Sensitive file names, matched against the last path segment(s). */
const SENSITIVE_FILE = [
  /(^|\/)\.env(\.[^/]+)?$/i, // .env, .env.local, .env.production ...
  /\.(pem|key|p12|pfx|jks|keystore)$/i,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/i, // ssh private keys (not .pub)
  /(^|\/)\.aws\/credentials$/i,
  /(^|\/)\.netrc$/i,
  /(^|\/)\.git-credentials$/i,
  /(^|\/)credentials\.json$/i,
  /(^|\/)service[-_]?account[^/]*\.json$/i,
]

/** True when the path points to a file that usually holds secrets. */
export function isSensitivePath(path: string): boolean {
  const p = path.replace(/\\/g, '/').replace(/["']/g, '')
  if (SAFE_ENV.test(p)) return false
  return SENSITIVE_FILE.some(re => re.test(p))
}

/** Returns the first sensitive path mentioned in a shell command, or undefined. */
export function findSensitivePathInCommand(command: string): string | undefined {
  const tokens = command.split(/[\s;|&<>()`=,]+/).filter(Boolean)
  return tokens.find(isSensitivePath)
}

/** Dangerous shell commands: [reason, pattern]. Matched case-insensitively. */
export const DANGEROUS_COMMANDS: ReadonlyArray<readonly [string, RegExp]> = [
  ['rm -rf (再帰的な強制削除)', /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r|--recursive\s+--force|--force\s+--recursive)\b/i],
  ['Remove-Item -Recurse -Force (再帰的な強制削除)', /\b(Remove-Item|rm|ri|del)\b(?=[^\n;|]*-Recurse)(?=[^\n;|]*-Force)/i],
  ['ダウンロードしたスクリプトを直接実行', /\b(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|iex|Invoke-Expression)\b/i],
  ['Invoke-Expression (文字列をコードとして実行)', /\b(iex|Invoke-Expression)\b/i],
  ['git push --force (リモート履歴の上書き)', /\bgit\s+push\b[^\n;|&]*(\s--force\b|\s-f\b|\s\+\S)/i],
  ['git reset --hard (未コミットの変更を破棄)', /\bgit\s+reset\b[^\n;|&]*--hard\b/i],
  ['git clean -f (未追跡ファイルを削除)', /\bgit\s+clean\b[^\n;|&]*-[a-z]*f/i],
  ['chmod 777 (誰でも書き込み可能にする)', /\bchmod\s+(-R\s+)?0?777\b/i],
  ['sudo (管理者権限での実行)', /(^|[\s;|&])sudo\s/i],
  ['ディスクの直接書き込み・フォーマット', /\b(mkfs(\.\w+)?|dd\s+[^\n]*of=\/dev\/|format\s+[a-z]:|diskpart)\b/i],
  ['実行ポリシーの変更', /\bSet-ExecutionPolicy\b/i],
  ['Windows Defender の無効化', /\bSet-MpPreference\b[^\n]*-Disable/i],
]

/** Returns the reason for the first dangerous pattern in `command`, or undefined. */
export function findDangerousCommand(command: string): string | undefined {
  for (const [reason, re] of DANGEROUS_COMMANDS) {
    if (re.test(command)) return reason
  }
  return undefined
}
