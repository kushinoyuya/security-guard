import type { Register } from 'claude-code'
import { findDangerousCommand, findSecret, findSensitivePathInCommand, isSensitivePath } from './rules'

const TAG = '[security-guard]'

/** What a call is about to write, or undefined when it writes nothing. */
function writtenText(e: { tool: string } & Record<string, unknown>): string | undefined {
  switch (e.tool) {
    case 'Write':
      return typeof e.content === 'string' ? e.content : undefined
    case 'Edit':
      return typeof e.new_string === 'string' ? e.new_string : undefined
    case 'NotebookEdit':
      return typeof e.new_source === 'string' ? e.new_source : undefined
    default:
      return undefined
  }
}

/** The file a file tool touches, or undefined. */
function touchedPath(e: { tool: string } & Record<string, unknown>): string | undefined {
  if (!['Read', 'Write', 'Edit', 'NotebookEdit'].includes(e.tool)) return undefined
  const p = e.file_path ?? e.notebook_path
  return typeof p === 'string' ? p : undefined
}

/** Why this call must be refused, or undefined to let it run. */
function denyReason(e: { tool: string } & Record<string, unknown>): string | undefined {
  // 1. Secrets written into files
  const text = writtenText(e)
  if (text !== undefined) {
    const found = findSecret(text)
    if (found) {
      return `${TAG} 書き込もうとした内容に秘密情報（${found}）が含まれているためブロックしました。` +
        'キーは環境変数や .env から読み込む形にし、コードには直接書かないでください。'
    }
  }

  // 2. Sensitive files touched by file tools
  const path = touchedPath(e)
  if (path !== undefined && isSensitivePath(path)) {
    return `${TAG} 機密ファイル（${path}）へのアクセスはブロックされています。` +
      '中身が必要な場合は、ユーザーに必要な値だけを教えてもらってください。'
  }

  // 3. Shell commands: secrets in the command line, or sensitive files named in it
  if ((e.tool === 'Bash' || e.tool === 'PowerShell') && typeof e.command === 'string') {
    const secret = findSecret(e.command)
    if (secret) {
      return `${TAG} コマンドに秘密情報（${secret}）が含まれているためブロックしました。`
    }
    const file = findSensitivePathInCommand(e.command)
    if (file) {
      return `${TAG} コマンドが機密ファイル（${file}）を参照しているためブロックしました。`
    }
  }
  return undefined
}

export const register: Register = on => {
  // Hard blocks: secrets and sensitive files.
  on('tool.call', ($, e, next) => {
    const reason = denyReason(e as unknown as { tool: string } & Record<string, unknown>)
    if (reason) {
      $.ui.toast(`🛡 ${reason}`)
      return { deny: reason }
    }
    return next(e)
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: `${TAG} チェック処理でエラーが起きたため、安全のためブロックしました。` },
  )

  // Soft guard: dangerous shell commands always ask the person first.
  on('tool.check', async ($, e, next) => {
    const verdict = await next(e)
    if (e.tool !== 'Bash' && e.tool !== 'PowerShell') return verdict
    if (verdict.decision === 'deny') return verdict

    const command = (e.input as { command?: unknown } | undefined)?.command
    if (typeof command !== 'string') return verdict

    const danger = findDangerousCommand(command)
    if (!danger) return verdict
    return { decision: 'ask', reason: `${TAG} 危険な操作の可能性があります: ${danger}。実行してよいか確認してください。` }
  }).catch(() => ({ decision: 'ask', reason: `${TAG} チェック処理でエラーが起きたため、確認をお願いします。` }))
}
