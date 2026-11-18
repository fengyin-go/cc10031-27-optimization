/** 凭据有效期 · 环境绑定 · 运行会话的数据契约（与后端 credential_* 接口一致）。 */

export type CredentialStatus = '正常' | '即将过期' | '已过期' | '已吊销'

export type BindingRecord = {
  binding_id: number
  target_system: string
  credential_id: number
  env_id: number | null
  effective_at: string
  expires_at: string | null
  status: string
  reason: string
  superseded_by: number | null
  terminal_state: string | null
}

export type SwitchRecord = {
  seq: number
  at: string
  target_system: string
  from_credential_id: number | null
  to_credential_id: number | null
  binding_id: number | null
  reason: string
  handling_item: string | null
  boundary: string | null
  boundary_label: string
}

export type CredentialView = {
  id: number
  name: string
  target_system: string
  auth_type: string
  account: string
  validity: string
  rotation_cycle: string
  last_used: string
  status: CredentialStatus
  remaining_days: number | null
  current_binding: {
    binding_id: number
    credential_id: number
    env_id: number | null
    status: string
    usable: boolean
  } | null
  standby_credential_id: number | null
  next_switch_at: string | null
  switch_reason: string
  switch_source: string
  switch_immediate: boolean
  history_only: boolean
  switch_records: SwitchRecord[]
}

export type ManifestItem = {
  target_system: string
  binding_id: number | null
  credential_id: number | null
  credential_name: string | null
  credential_status: string | null
  credential_validity: string | null
  env_id: number | null
  expires_at: string | null
  next_switch_at: string | null
  switch_reason: string
  switch_immediate?: boolean
  standby_credential_id: number | null
  executable: boolean
  blocked_reason: string | null
  excluded_credentials: { credential_id: number; credential_name: string; status: string }[]
}

export type ExecutableManifest = {
  handling_item: string | null
  generated_at: string
  manifest_digest: string
  executable: boolean
  items: ManifestItem[]
  blocked: { target_system: string; reason: string }[]
  excluded_credentials: { credential_id: number; target_system: string; status: string }[]
}

export type SessionAssignment = {
  binding_id: number
  credential_id: number
  credential_name: string
  credential_validity: string
  env_id: number | null
  next_switch_at: string | null
  switch_reason: string
}

export type RuntimeCredentialSession = {
  session_id: string
  handling_item: string
  boundary: string
  boundary_label: string
  manifest_digest: string
  status: string
  assignments: Record<string, SessionAssignment>
  created_at: string
  updated_at: string
  resumes: number
  dedup_hits: number
  counted_runs: number
  blocked_reason: string | null
  terminal_state: string | null
  switches: { at: string; target_system: string; from_credential_id: number; to_credential_id: number; reason: string }[]
}

export type CredentialWorkbench = {
  generated_at: string
  summary: {
    total: number
    normal: number
    expiring: number
    expired: number
    revoked: number
    history_only: number
  }
  credentials: CredentialView[]
  bindings: BindingRecord[]
  switch_records: SwitchRecord[]
  manifest: ExecutableManifest
  boundaries: { key: string; label: string }[]
  sessions: RuntimeCredentialSession[]
}

export type SessionOperationResult = {
  ok: boolean
  message?: string
  deduplicated?: boolean
  counted_runs?: number
  used_expired_credential?: boolean
  conflict?: boolean
  terminal_state?: string
  session?: RuntimeCredentialSession
}
