/** 凭据有效期 · 环境绑定 · 运行会话的接口封装。 */
import { request } from './client'
import type {
  CredentialWorkbench,
  ExecutableManifest,
  SessionOperationResult,
} from '@/domain/credential-binding'

async function postJson<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await request(path, {
    method: 'POST',
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error('操作请求失败')
  return (await response.json()) as T
}

export async function loadCredentialWorkbench(): Promise<CredentialWorkbench> {
  const response = await request('/api/credential-workbench')
  if (!response.ok) throw new Error('凭据工作台读取失败')
  return await response.json()
}

export async function loadCredentialManifest(
  targetSystem?: string,
): Promise<ExecutableManifest> {
  const query = targetSystem ? `?target_system=${encodeURIComponent(targetSystem)}` : ''
  const response = await request(`/api/credential-manifest${query}`)
  if (!response.ok) throw new Error('可执行绑定清单读取失败')
  return await response.json()
}

export async function startCredentialSession(
  handlingItem: string,
  boundary: string,
): Promise<SessionOperationResult> {
  return postJson<SessionOperationResult>('/api/credential-sessions', {
    handling_item: handlingItem,
    boundary,
  })
}

export async function reportSessionExpiry(
  sessionId: string,
  boundary: string,
): Promise<SessionOperationResult> {
  return postJson<SessionOperationResult>(
    `/api/credential-sessions/${sessionId}/expiry`,
    { boundary },
  )
}

export async function resumeCredentialSession(
  sessionId: string,
): Promise<SessionOperationResult> {
  return postJson<SessionOperationResult>(`/api/credential-sessions/${sessionId}/resume`)
}

export async function archiveCredentialSession(
  sessionId: string,
): Promise<SessionOperationResult> {
  return postJson<SessionOperationResult>(`/api/credential-sessions/${sessionId}/archive`)
}
